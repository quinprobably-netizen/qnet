import QtQuick
import qs.Commons

// Everything the card holds, top to bottom: the connection, the DNS hero, a
// divider, any leaks, the DNS tiles, the networks, the IP footer. Panel.qml
// owns the state and the keys and hands itself in as `hub`.
Column {
  id: body

  required property var hub
  property alias networks: networks

  width: parent ? parent.width : 0
  spacing: 0

  Header { hub: body.hub }
  DnsHero { hub: body.hub }

  // The hero ends here.
  Item {
    width: body.width
    height: Style.space(10)
    Rectangle {
      x: body.hub.gutter
      y: Style.space(3)
      width: parent.width - 2 * body.hub.gutter
      height: 1
      color: body.hub.lineColor
    }
  }

  LeakLines { hub: body.hub }
  DnsRow { hub: body.hub }
  NetworkList { id: networks; hub: body.hub }
  IpFooter { hub: body.hub }
}
