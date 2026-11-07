import QtQuick

// The Wi-Fi view: the networks, the one in use first (with Disconnect, and
// Forget on a secondary click or Delete), saved ones marked "Saved", a
// passphrase row under a secured network you pick, and the scan with its age.
// Entering this view runs `qnet wifi scan --if-stale 60`; the panel never
// scans just because it opened.
Column {
  id: view

  required property var hub
  property alias networks: networks

  width: parent ? parent.width : 0
  spacing: 0

  ViewHeader {
    hub: view.hub
    title: view.hub.strings.t("view.wifi")
    subtitle: view.hub.wifiSubtitle
  }

  NetworkList { id: networks; hub: view.hub }
}
