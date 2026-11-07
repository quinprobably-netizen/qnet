import QtQuick

// Everything the card holds, top to bottom: the connection, the DNS hero,
// any leaks, the DNS row, the networks, the IP footer. Panel.qml owns the
// state and the keys and hands itself in as `hub`.
Column {
  id: body

  required property var hub
  property alias networks: networks

  width: parent ? parent.width : 0
  spacing: 0

  Header { hub: body.hub }
  DnsHero { hub: body.hub }
  LeakLines { hub: body.hub }
  DnsRow { hub: body.hub }
  NetworkList { id: networks; hub: body.hub }
  IpFooter { hub: body.hub }
}
