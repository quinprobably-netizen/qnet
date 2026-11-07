import QtQuick
import qs.Commons

// The main view, top to bottom: the connection, the hero (the Pi-hole's day,
// its state, the one thing to do if something is wrong, and the route, whose
// nodes open the Wi-Fi and DNS views), the Pause tile, and the address.
// Nothing here scans.
Column {
  id: main

  required property var hub

  width: parent ? parent.width : 0
  spacing: 0

  Header { hub: main.hub }
  Hero { hub: main.hub }
  PauseTile { hub: main.hub }
  Hairline { hub: main.hub; above: Style.space(10); below: Style.space(2) }
  IpFooter { hub: main.hub }
}
