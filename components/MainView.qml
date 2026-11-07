import QtQuick
import qs.Commons

// The main view, top to bottom: the connection, the hero (the Pi-hole's day,
// its state, and the one thing to do if something is wrong), the Pause tile, a
// hairline, two rows that open the DNS and Wi-Fi views (Sound Hub's "Bluetooth
// ›" pattern), a hairline, and the address footer. Nothing here scans.
Column {
  id: main

  required property var hub

  width: parent ? parent.width : 0
  spacing: 0

  Header { hub: main.hub }
  Hero { hub: main.hub }
  PauseTile { hub: main.hub }
  Hairline { hub: main.hub; above: Style.space(10); below: Style.space(4) }

  DrillRow {
    hub: main.hub
    name: main.hub.strings.t("view.dns")
    cursorRow: "goto:dns"
    value: main.hub.dnsRowValue.text
    tone: main.hub.dnsRowValue.tone
    tipText: main.hub.strings.t("view.dnsTip")
    onActivated: main.hub.openView("dns")
  }

  DrillRow {
    hub: main.hub
    name: main.hub.strings.t("view.wifi")
    cursorRow: "goto:wifi"
    value: main.hub.wifiRowValue
    tipText: main.hub.strings.t("view.wifiTip")
    onActivated: main.hub.openView("wifi")
  }

  Hairline { hub: main.hub; above: Style.space(4); below: Style.space(0) }
  IpFooter { hub: main.hub }
}
