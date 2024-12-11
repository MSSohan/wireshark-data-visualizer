import pyshark
from pychart import theme, axis, line_plot, area, canvas, legend, chart_object

# Load PCAP file using pyshark
pcap_file = 'example.pcap'  # Replace with your PCAP file
cap = pyshark.FileCapture(pcap_file)

# Extract timestamps and packet numbers
timestamps = []
packet_numbers = []

for index, packet in enumerate(cap):
    timestamps.append(float(packet.sniff_timestamp))  # Convert timestamp to float
    packet_numbers.append(index + 1)

cap.close()

# Prepare the data
data = list(zip(packet_numbers, timestamps))

# Configure PyChart theme
theme.use_color = 1
theme.default_font_size = 14
theme.reinitialize()

# Create a chart area
chart_area = area.T(
    x_coord=axis.X(label="Packet Number", format="%d"),
    y_coord=axis.Y(label="Timestamp (s)", format="%.2f"),
    legend=legend.T(),
)

# Add a line plot
chart_area.add_plot(line_plot.T(label="Packet Timestamps", data=data))

# Draw the chart
canvas.init("time_plot.png")
chart_area.draw()
canvas.finish()

print("Time plot saved as 'time_plot.png'")
