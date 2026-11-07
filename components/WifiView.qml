import QtQuick

// The Wi-Fi view, as a network settings page is laid out: the connection in
// use as a card of key/value lines (with Disconnect), then the networks in
// range, strongest first, with the scan and its age in the head. A saved one
// says "Saved"; a secured one that is not saved wears a lock and asks for its
// passphrase in a row under it. Entering this view runs `qnet wifi scan
// --if-stale 60`; the panel never scans just because it opened.
Column {
  id: view

  required property var hub
  property alias networks: networks

  width: parent ? parent.width : 0
  spacing: 0

  ViewHeader {
    hub: view.hub
    title: view.hub.strings.t("view.wifi")
  }

  ConnectionCard { hub: view.hub }
  NearbyList { id: networks; hub: view.hub }
}
