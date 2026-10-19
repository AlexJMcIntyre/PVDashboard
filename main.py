import gc
import socket
import struct
import time
import ujson
import ubinascii
import urandom

from urllib import urequest

import inky_helper as ih
import inky_frame

from secrets import WIFI_SSID, WIFI_PASSWORD, HA_URL, HA_TOKEN

from picographics import (
    PicoGraphics,
    DISPLAY_INKY_FRAME_SPECTRA_7,
)

# ============================================================
# Configuration
# ============================================================

REFRESH_MINUTES = 15
HISTORY_SECONDS = 24 * 60 * 60
FORECAST_SECONDS = 24 * 60 * 60

# Set these to any #RRGGBB hex colours. Keep the keys as they are; each key
# controls the matching dashboard series or display element.
COLOUR_HEX = {
    "background": "#FFFFFF",
    "text": "#000000",
    "grid": "#000000",
    "pv": "#ff8400",
    "import": "#FF0000",
    "export": "#0000FF",
    "soc": "#00FF00",
    "cheap": "#b3ffb3",
    "standard": "#FFFFFF",
    "expensive": "#ffb3b3",
}

# The most frequently occurring rate is the standard tariff band. Rates below
# it are cheap, and rates above it are expensive.

SENSORS = [
    "sensor.pv_power",
    "sensor.grid_consumption",
    "sensor.feed_in",
    "sensor.battery_soc",
]

graphics = PicoGraphics(DISPLAY_INKY_FRAME_SPECTRA_7)
WIDTH, HEIGHT = graphics.get_bounds()


def make_colour_pens():
    pens = {}
    for name, value in COLOUR_HEX.items():
        colour = value.lstrip("#")
        if len(colour) != 6:
            raise ValueError("{} colour must be #RRGGBB".format(name))
        try:
            red = int(colour[0:2], 16)
            green = int(colour[2:4], 16)
            blue = int(colour[4:6], 16)
        except ValueError:
            raise ValueError("{} colour must be #RRGGBB".format(name))
        pens[name] = graphics.create_pen(red, green, blue)
    return pens


COLOUR = make_colour_pens()

# Display layout
LEFT = 65
RIGHT = WIDTH - 245

GRAPH_WIDTH = RIGHT - LEFT



# ============================================================
# WebSocket client
# ============================================================

def make_mask():
    return bytes(urandom.getrandbits(8) for _ in range(4))


def recv_exact(sock, length):
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise OSError("Connection closed unexpectedly")

        data.extend(chunk)

    return bytes(data)


class WebSocket:
    def __init__(self, sock):
        self.sock = sock

    def send_text(self, message):
        payload = message.encode()
        length = len(payload)
        mask = make_mask()

        if length < 126:
            header = bytes((0x81, 0x80 | length))
        elif length < 65536:
            header = bytes((0x81, 0x80 | 126))
            header += struct.pack("!H", length)
        else:
            raise ValueError("Outgoing message too large")

        masked = bytearray(length)

        for i in range(length):
            masked[i] = payload[i] ^ mask[i & 3]

        self.sock.send(header + mask + masked)

    def recv_text(self):
        while True:
            first, second = recv_exact(self.sock, 2)

            opcode = first & 0x0F
            length = second & 0x7F

            if length == 126:
                length = struct.unpack(
                    "!H", recv_exact(self.sock, 2)
                )[0]
            elif length == 127:
                length = struct.unpack(
                    "!Q", recv_exact(self.sock, 8)
                )[0]

            masked = bool(second & 0x80)
            mask = recv_exact(self.sock, 4) if masked else None

            payload = bytearray(recv_exact(self.sock, length))

            if masked:
                for i in range(length):
                    payload[i] ^= mask[i & 3]

            if opcode == 8:
                raise OSError("WebSocket closed by server")

            if opcode == 9:
                self.send_control(10, payload)
                continue

            if opcode == 10:
                continue

            if opcode == 1:
                return payload.decode()

            if opcode == 2:
                raise ValueError("Unexpected binary frame")

    def send_control(self, opcode, payload):
        length = len(payload)
        mask = make_mask()

        header = bytes((0x80 | opcode, 0x80 | length))
        masked = bytearray(length)

        for i in range(length):
            masked[i] = payload[i] ^ mask[i & 3]

        self.sock.send(header + mask + masked)


def connect_websocket():
    host = HA_URL.replace("http://", "").replace("https://", "")
    host = host.split("/")[0]

    parts = host.split(":")
    hostname = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 80

    sock = socket.socket()
    sock.connect((hostname, port))

    key = ubinascii.b2a_base64(
        bytes(urandom.getrandbits(8) for _ in range(16))
    ).strip().decode()

    request = (
        "GET /api/websocket HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: {}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).format(host, key)

    sock.send(request.encode())

    response = bytearray()

    while b"\r\n\r\n" not in response:
        chunk = sock.recv(256)

        if not chunk:
            raise OSError("WebSocket handshake failed")

        response.extend(chunk)

    headers = bytes(response).split(b"\r\n\r\n", 1)[0]
    status_line = headers.split(b"\r\n")[0]


    if b"101" not in status_line:
        sock.close()
        raise OSError("WebSocket upgrade rejected")

    return WebSocket(sock)


# ============================================================
# Home Assistant statistics
# ============================================================

def iso_utc(timestamp):
    t = time.gmtime(timestamp)

    return (
        "{:04d}-{:02d}-{:02d}T"
        "{:02d}:{:02d}:{:02d}Z"
    ).format(
        t[0], t[1], t[2],
        t[3], t[4], t[5]
    )


def fetch_statistics(utc_offset_seconds=0):
    now = time.time() - utc_offset_seconds
    start = now - HISTORY_SECONDS


    ws = None

    try:
        ws = connect_websocket()

        greeting = ujson.loads(ws.recv_text())

        if greeting.get("type") != "auth_required":
            raise OSError("Unexpected WebSocket greeting")

        ws.send_text(ujson.dumps({
            "type": "auth",
            "access_token": HA_TOKEN,
        }))

        auth = ujson.loads(ws.recv_text())

        if auth.get("type") != "auth_ok":
            raise OSError("Home Assistant authentication failed")

        ws.send_text(ujson.dumps({
            "id": 1,
            "type": "recorder/statistics_during_period",
            "start_time": iso_utc(start),
            "end_time": iso_utc(now),
            "statistic_ids": SENSORS,
            "period": "5minute",
            "types": ["mean", "min", "max"],
        }))

        response = ujson.loads(ws.recv_text())

        if not response.get("success"):
            print("Statistics error:", response.get("error"))
            return None

        result = response.get("result", {})

        return result

    finally:
        if ws is not None:
            ws.sock.close()

        gc.collect()


# ============================================================
# Home Assistant entity states
# ============================================================

def get_ha_state(entity_id):
    response = None

    try:
        url = HA_URL + "/api/states/" + entity_id

        response = urequest.urlopen(
            url,
            headers={
                "Authorization": "Bearer " + HA_TOKEN,
            },
        )

        return ujson.loads(response.read())

    finally:
        if response is not None:
            response.close()


def fetch_predbat():
    forecast_entity = get_ha_state("predbat.soc_kw_best")
    rates_entity = get_ha_state("predbat.rates")

    forecast = forecast_entity.get(
        "attributes", {}
    ).get("results", {})

    rates = rates_entity.get(
        "attributes", {}
    ).get("results", {})

    soc_max = float(
        forecast_entity.get(
            "attributes", {}
        ).get("soc_max", 5.76)
    )


    return forecast, rates, soc_max


# ============================================================
# Timestamp conversion
# ============================================================

def timestamp_to_epoch(value):
    """
    Convert ISO timestamps such as:
    2026-10-16T00:45:00+0100

    into Unix epoch seconds without relying on strptime().
    """
    date_part, time_part = value.split("T")

    year, month, day = [
        int(x) for x in date_part.split("-")
    ]

    if "+" in time_part:
        clock, offset = time_part.split("+")
        sign = 1
    elif "-" in time_part:
        clock, offset = time_part.split("-")
        sign = -1
    else:
        clock = time_part
        offset = "0000"
        sign = 1

    clock_parts = clock.split(":")
    hour = int(clock_parts[0])
    minute = int(clock_parts[1])
    second = int(float(clock_parts[2]))

    offset_hours = int(offset[:2])
    offset_minutes = int(offset[2:])

    offset_seconds = sign * (
        offset_hours * 3600
        + offset_minutes * 60
    )

    adjusted_year = year - (1 if month <= 2 else 0)
    era = adjusted_year // 400
    year_of_era = adjusted_year - era * 400

    adjusted_month = month + (-3 if month > 2 else 9)

    day_of_year = (
        (153 * adjusted_month + 2) // 5
        + day - 1
    )

    day_of_era = (
        year_of_era * 365
        + year_of_era // 4
        - year_of_era // 100
        + day_of_year
    )

    days = era * 146097 + day_of_era - 719468

    local_seconds = (
        days * 86400
        + hour * 3600
        + minute * 60
        + second
    )

    return local_seconds - offset_seconds


# ============================================================

def timestamp_utc_offset_seconds(value):
    """Return the UTC offset encoded in an ISO timestamp."""
    time_part = value.split("T", 1)[1]
    if "+" in time_part:
        offset = time_part.rsplit("+", 1)[1]
        sign = 1
    elif "-" in time_part:
        offset = time_part.rsplit("-", 1)[1]
        sign = -1
    else:
        return 0
    offset = offset.replace(":", "")
    hours = int(offset[:2])
    minutes = int(offset[2:4]) if len(offset) >= 4 else 0
    return sign * (hours * 3600 + minutes * 60)


def timezone_offset_at(timestamp, rates):
    """Get the tariff timezone offset for a timestamp."""
    selected_epoch = None
    selected_offset = 0
    for rate_timestamp in rates:
        try:
            epoch = timestamp_to_epoch(rate_timestamp)
            offset = timestamp_utc_offset_seconds(rate_timestamp)
            if epoch <= timestamp and (selected_epoch is None or epoch > selected_epoch):
                selected_epoch = epoch
                selected_offset = offset
            elif selected_epoch is None:
                selected_epoch = epoch
                selected_offset = offset
        except Exception:
            pass
    return selected_offset

def modal_tariff_price(rates):
    """Return the most common rate, resolving ties toward the median rate."""
    prices = []
    for price in rates.values():
        try:
            prices.append(float(price))
        except Exception:
            pass

    if not prices:
        return None

    prices.sort()

    counts = {}
    for price in prices:
        counts[price] = counts.get(price, 0) + 1

    highest_count = max(counts.values())
    median = prices[len(prices) // 2]
    candidates = [price for price in counts if counts[price] == highest_count]
    selected = candidates[0]
    for price in candidates[1:]:
        if abs(price - median) < abs(selected - median):
            selected = price
    return selected


def tariff_band(price, rates):
    standard_price = modal_tariff_price(rates)
    if standard_price is None:
        return "UNKNOWN"
    if price < standard_price:
        return "CHEAP"
    if price > standard_price:
        return "EXPENSIVE"
    return "STANDARD"


def current_tariff_label(rates, now):
    latest_epoch = None
    latest_price = None

    for timestamp, price in rates.items():
        try:
            epoch = timestamp_to_epoch(timestamp)
            if epoch <= now and (latest_epoch is None or epoch > latest_epoch):
                latest_epoch = epoch
                latest_price = float(price)
        except Exception:
            pass

    band = tariff_band(latest_price, rates) if latest_price is not None else "UNKNOWN"
    colours = {
        "CHEAP": COLOUR["cheap"],
        "STANDARD": COLOUR["standard"],
        "EXPENSIVE": COLOUR["expensive"],
        "UNKNOWN": COLOUR["text"],
    }
    return band, colours[band]

def format_energy_state(value):
    if value is None:
        return "-- kWh"
    return "{:.2f} kWh".format(value)


def numeric_entity_state(entity_id):
    try:
        entity = get_ha_state(entity_id)
        return float(entity.get("state"))
    except Exception:
        return None
# Drawing helpers
# ============================================================

def draw_label(text, x, y, scale=1):
    graphics.set_pen(COLOUR["text"])
    graphics.text(
        str(text),
        int(x),
        int(y),
        WIDTH,
        scale
    )


def draw_segment(x1, y1, x2, y2, colour):
    graphics.set_pen(colour)

    graphics.line(
        int(x1), int(y1),
        int(x2), int(y2)
    )


def dynamic_power_axis(data):
    """Choose a readable kW scale from the history values."""
    maximum = 0.0
    for entity_id in ("sensor.pv_power", "sensor.grid_consumption", "sensor.feed_in"):
        for point in data.get(entity_id, []):
            value = point.get("mean")
            if value is not None:
                try:
                    maximum = max(maximum, float(value))
                except Exception:
                    pass

    if maximum <= 0:
        return 1.0, 0.2

    rough_step = maximum / 5.0
    magnitude = 1.0
    while magnitude > rough_step:
        magnitude /= 10.0
    while magnitude * 10.0 < rough_step:
        magnitude *= 10.0

    step = 10.0 * magnitude
    for candidate in (1.0, 2.0, 2.5, 5.0, 10.0):
        if candidate * magnitude >= rough_step:
            step = candidate * magnitude
            break

    axis_max = step
    while axis_max < maximum:
        axis_max += step

    return axis_max, step


def draw_pv_segment(x1, y1, x2, y2):
    """Draw the PV trace using its configured single colour."""
    draw_wide_segment(x1, y1, x2, y2, COLOUR["pv"])


def draw_dotted_segment(x1, y1, x2, y2, colour):
    """Draw a short dotted line using small marks with regular gaps."""
    x1 = int(x1)
    y1 = int(y1)
    x2 = int(x2)
    y2 = int(y2)
    dx = x2 - x1
    dy = y2 - y1
    steps = max(abs(dx), abs(dy))

    if steps == 0:
        draw_segment(x1, y1, x2, y2, colour)
        return

    position = 0
    while position <= steps:
        dash_end = min(position + 1, steps)
        sx = x1 + (dx * position) // steps
        sy = y1 + (dy * position) // steps
        ex = x1 + (dx * dash_end) // steps
        ey = y1 + (dy * dash_end) // steps
        draw_segment(sx, sy, ex, ey, colour)
        position += 5


def draw_wide_segment(x1, y1, x2, y2, colour):
    """Draw a three-pixel data line while keeping chart grids thin."""
    dx = abs(int(x2) - int(x1))
    dy = abs(int(y2) - int(y1))

    if dx >= dy:
        for offset in (-1, 0, 1):
            draw_segment(x1, y1 + offset, x2, y2 + offset, colour)
    else:
        for offset in (-1, 0, 1):
            draw_segment(x1 + offset, y1, x2 + offset, y2, colour)


def graph_x(timestamp, start, end, left, right):
    if end <= start:
        return left

    fraction = (timestamp - start) / (end - start)

    return int(left + fraction * (right - left))


def draw_clock_grid(start, end, left, right, top, bottom, offset_seconds, label_y):
    """Draw gridlines at local midnight and every three hours."""
    local_start = time.gmtime(start + offset_seconds)
    local_midnight = "{}-{:02d}-{:02d}T00:00:00".format(local_start[0], local_start[1], local_start[2])
    offset_sign = "+" if offset_seconds >= 0 else "-"
    offset_minutes = abs(offset_seconds) // 60
    offset_text = "{}{:02d}{:02d}".format(offset_sign, offset_minutes // 60, offset_minutes % 60)
    tick = timestamp_to_epoch(local_midnight + offset_text)
    while tick <= end:
        if tick >= start:
            x = graph_x(tick, start, end, left, right)
            local_hour = time.gmtime(tick + offset_seconds)[3]
            draw_dotted_segment(x, top, x, bottom, COLOUR["grid"])
            draw_label("{:02d}".format(local_hour), x - 12, label_y, 2)
        tick += 3 * 3600

def graph_y(value, minimum, maximum, top, bottom):
    if maximum <= minimum:
        return bottom

    fraction = (float(value) - minimum) / (maximum - minimum)

    return int(bottom - fraction * (bottom - top))


def draw_time_labels(start, end, left, right, y):
    for hour in (0, 6, 12, 18, 24):
        timestamp = start + hour * 3600

        if timestamp > end:
            continue

        x = graph_x(timestamp, start, end, left, right)

        draw_label(
            "{:02d}".format(time.gmtime(timestamp)[3]),
            x - 8,
            y,
            1
        )


def draw_legend(items, y):
    """
    items contains (label, colour, x) tuples.
    """
    for label, colour, x in items:
        box_x = int(x)
        box_y = int(y + 3)
        graphics.set_pen(colour)
        graphics.rectangle(box_x, box_y, 14, 10)
        # Outline keeps the white standard swatch visible on a white page.
        draw_segment(box_x, box_y, box_x + 13, box_y, COLOUR["text"])
        draw_segment(box_x, box_y + 9, box_x + 13, box_y + 9, COLOUR["text"])
        draw_segment(box_x, box_y, box_x, box_y + 9, COLOUR["text"])
        draw_segment(box_x + 13, box_y, box_x + 13, box_y + 9, COLOUR["text"])

        draw_label(label, x + 19, y, 2)


# ============================================================
# Historical chart
# ============================================================

def draw_history(data, now, rates):
    left = LEFT
    right = RIGHT

    top = 52
    bottom = 193

    start = now - HISTORY_SECONDS
    end = now

    # Show each tariff band as a pale background behind the history traces.
    rate_points = []
    for timestamp, price in rates.items():
        try:
            rate_points.append((timestamp_to_epoch(timestamp), float(price)))
        except Exception:
            pass
    rate_points.sort(key=lambda item: item[0])
    for i in range(len(rate_points)):
        period_start, price = rate_points[i]
        period_end = rate_points[i + 1][0] if i + 1 < len(rate_points) else end
        period_start = max(period_start, start)
        period_end = min(period_end, end)
        if period_end <= period_start:
            continue
        band = tariff_band(price, rates)
        if band in ("CHEAP", "EXPENSIVE"):
            x1 = graph_x(period_start, start, end, left, right)
            x2 = graph_x(period_end, start, end, left, right)
            graphics.set_pen(COLOUR[band.lower()])
            graphics.rectangle(x1, top, max(1, x2 - x1), bottom - top)

    # Dynamic kW scale and grid.
    power_max, power_step = dynamic_power_axis(data)
    draw_label("kW", 20, top - 15, 1)
    kw = 0.0
    while kw <= power_max + power_step * 0.001:
        y = graph_y(kw, 0, power_max, top, bottom)
        draw_dotted_segment(left, y, right, y, COLOUR["grid"])
        kw_label = "{:.2f}".format(kw).rstrip("0").rstrip(".")
        draw_label(kw_label, 34, y - 9, 2)
        kw += power_step
    # Battery SoC labels on the right.
    for percent in (0, 50, 100):
        y = graph_y(percent, 0, 100, top, bottom)
        draw_label(str(percent), right + 8, y - 9, 2)

    # Clock-aligned gridlines, every three local hours.
    offset_seconds = timezone_offset_at(now, rates)
    draw_clock_grid(start, end, left, right, top, bottom, offset_seconds, bottom + 3)

    # PV, grid import and export.
    for entity_id, colour in (
        ("sensor.pv_power", COLOUR["pv"]),
        ("sensor.grid_consumption", COLOUR["import"]),
        ("sensor.feed_in", COLOUR["export"]),
    ):
        points = data.get(entity_id, [])
        previous = None

        for point in points:
            timestamp = point.get("start")
            value = point.get("mean")

            if timestamp is None or value is None:
                previous = None
                continue

            timestamp = timestamp / 1000

            x = graph_x(timestamp, start, end, left, right)
            y = graph_y(value, 0, power_max, top, bottom)

            if previous is not None:
                if entity_id == "sensor.pv_power":
                    draw_pv_segment(previous[0], previous[1], x, y)
                else:
                    draw_wide_segment(
                        previous[0], previous[1],
                        x, y,
                        colour
                    )

            previous = (x, y)

    # Battery SoC.
    previous = None

    for point in data.get("sensor.battery_soc", []):
        timestamp = point.get("start")
        value = point.get("mean")

        if timestamp is None or value is None:
            previous = None
            continue

        timestamp = timestamp / 1000

        x = graph_x(timestamp, start, end, left, right)
        y = graph_y(value, 0, 100, top, bottom)

        if previous is not None:
            draw_wide_segment(
                previous[0], previous[1],
                x, y,
                COLOUR["soc"]
            )

        previous = (x, y)

    draw_legend([
        ("PV", COLOUR["pv"], 35),
        ("IMPORT", COLOUR["import"], 150),
        ("EXPORT", COLOUR["export"], 310),
        ("SOC", COLOUR["soc"], 490),
    ], 226)


# ============================================================
# Forecast chart
# ============================================================

def draw_forecast(forecast, rates, soc_max, now):
    left = LEFT
    right = RIGHT

    top = 288
    bottom = 421

    start = now
    end = now + FORECAST_SECONDS

    # Parse and sort tariff entries.
    rate_points = []

    for timestamp, price in rates.items():
        try:
            epoch = timestamp_to_epoch(timestamp)
            offset = timestamp_utc_offset_seconds(timestamp)
            rate_points.append((epoch, float(price), offset, timestamp))
        except Exception as e:
            pass

    rate_points.sort(key=lambda item: item[0])

    # Background tariff bands.
    for i in range(len(rate_points)):
        period_start, price, offset, raw_timestamp = rate_points[i]

        if i + 1 < len(rate_points):
            period_end = rate_points[i + 1][0]
        else:
            period_end = end

        period_start = max(period_start, start)
        period_end = min(period_end, end)

        if period_end <= period_start:
            continue

        x1 = graph_x(period_start, start, end, left, right)
        x2 = graph_x(period_end, start, end, left, right)

        band = tariff_band(price, rates)
        colour = COLOUR[band.lower()]

        graphics.set_pen(colour)
        graphics.rectangle(
            x1,
            top,
            max(1, x2 - x1),
            bottom - top
        )

    # Grid and SoC labels.
    for percent in (0, 25, 50, 75, 100):
        y = graph_y(percent, 0, 100, top, bottom)

        draw_dotted_segment(left, y, right, y, COLOUR["grid"])
        draw_label(str(percent), 34, y - 9, 2)

    # Forecast values are kWh. Convert to SoC percentage.
    forecast_points = []

    for timestamp, value in forecast.items():
        try:
            epoch = timestamp_to_epoch(timestamp)
            percent = (float(value) / soc_max) * 100

            if start <= epoch <= end:
                forecast_points.append((epoch, percent))

        except Exception as e:
            pass

    forecast_points.sort(key=lambda item: item[0])

    previous = None

    for timestamp, percent in forecast_points:
        x = graph_x(timestamp, start, end, left, right)
        y = graph_y(percent, 0, 100, top, bottom)

        if previous is not None:
            draw_wide_segment(
                previous[0], previous[1],
                x, y,
                COLOUR["text"]
            )

        previous = (x, y)

    # Clock-aligned gridlines, every three local hours.
    offset_seconds = timezone_offset_at(now, rates)
    draw_clock_grid(start, end, left, right, top, bottom, offset_seconds, bottom + 3)
    # Compact tariff legend.
    draw_legend([
        ("CHEAP", COLOUR["cheap"], 40),
        ("STANDARD", COLOUR["standard"], 200),
        ("EXPENSIVE", COLOUR["expensive"], 390),
    ], 450)


# ============================================================
# Full dashboard
# ============================================================


def draw_indicators(rates, now, battery_soc, pv_kwh, export_kwh, import_kwh, utc_offset):
    panel_x = RIGHT + 64
    separator_x = RIGHT + 48
    draw_dotted_segment(separator_x, 15, separator_x, HEIGHT - 15, COLOUR["grid"])

    draw_label("BATTERY SOC", panel_x, 24, 1)
    if battery_soc is None:
        battery_text = "--%"
    else:
        battery_text = "{:.0f}%".format(battery_soc)
    draw_label(battery_text, panel_x, 40, 3)

    draw_label("PV TODAY", panel_x, 96, 1)
    draw_label(format_energy_state(pv_kwh), panel_x, 112, 2)

    draw_label("EXPORT TODAY", panel_x, 158, 1)
    draw_label(format_energy_state(export_kwh), panel_x, 174, 2)

    draw_label("IMPORT TODAY", panel_x, 220, 1)
    draw_label(format_energy_state(import_kwh), panel_x, 236, 2)

    tariff_label, tariff_colour = current_tariff_label(rates, now)
    draw_label("ELECTRICITY", panel_x, 282, 1)
    badge_x = int(panel_x)
    badge_y = 298
    badge_width = 140
    badge_height = 28
    graphics.set_pen(tariff_colour)
    graphics.rectangle(badge_x, badge_y, badge_width, badge_height)
    draw_segment(badge_x, badge_y, badge_x + badge_width - 1, badge_y, COLOUR["text"])
    draw_segment(badge_x, badge_y + badge_height - 1, badge_x + badge_width - 1, badge_y + badge_height - 1, COLOUR["text"])
    draw_segment(badge_x, badge_y, badge_x, badge_y + badge_height - 1, COLOUR["text"])
    draw_segment(badge_x + badge_width - 1, badge_y, badge_x + badge_width - 1, badge_y + badge_height - 1, COLOUR["text"])
    graphics.set_pen(COLOUR["text"])
    graphics.text(tariff_label, badge_x + 6, badge_y + 4, WIDTH, 2)

    local_now = time.gmtime(now + utc_offset)
    draw_label("LAST UPDATE", panel_x, 368, 1)
    draw_label("{:02d}/{:02d} {:02d}:{:02d}".format(
        local_now[2], local_now[1], local_now[3], local_now[4]
    ), panel_x, 384, 2)
def draw_dashboard(data, forecast, rates, soc_max, battery_soc, pv_kwh, export_kwh, import_kwh):
    graphics.set_pen(COLOUR["background"])
    graphics.clear()

    now = time.time()
    utc_offset = timezone_offset_at(now, rates)

    draw_label("LAST 24 HOURS", 25, 14, 2)

    draw_history(data, now, rates)

    draw_label("NEXT 24 HOURS", 25, 260, 2)

    draw_forecast(forecast, rates, soc_max, now)
    draw_indicators(rates, now, battery_soc, pv_kwh, export_kwh, import_kwh, utc_offset)

    graphics.update()


# ============================================================
# Main
# ============================================================

def main():
    try:
        ih.network_connect(WIFI_SSID, WIFI_PASSWORD)

        try:
            inky_frame.set_time()
        except Exception:
            pass

        gc.collect()

        forecast, rates, soc_max = fetch_predbat()

        gc.collect()

        data = fetch_statistics()

        if data is None:
            print("No historical statistics received.")
            return

        gc.collect()

        battery_soc = numeric_entity_state("sensor.battery_soc")
        pv_kwh = numeric_entity_state("sensor.solar_energy_today")
        import_kwh = numeric_entity_state("sensor.grid_consumption_energy_today")
        export_kwh = numeric_entity_state("sensor.feed_in_energy_today")

        draw_dashboard(data, forecast, rates, soc_max, battery_soc, pv_kwh, export_kwh, import_kwh)


    except Exception as e:
        print("Dashboard update failed:", repr(e))

    finally:
        gc.collect()

    inky_frame.sleep_for(REFRESH_MINUTES)


main()




