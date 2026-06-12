#!/usr/bin/env python3
"""
Unit tests for the clock-fix PUT-body builders and namespace capture.

Runs with NO network and NO device contact — it validates the write-payload
logic against REAL captured Hikvision XML namespace variants before any live
NVR is ever touched. Run: python3 test_clock_fix.py
"""
import xml.etree.ElementTree as ET
import clock_fix as cf

# Real /ISAPI/System/time responses observed on this fleet (namespaces differ
# per firmware AND per endpoint — that's exactly why we capture per-request).
FIXTURES = {
    'isapi.org v2.0 (Site A time endpoint)': (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<Time version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">\n'
        '<timeMode>manual</timeMode>\n'
        '<localTime>2026-05-29T15:33:42+04:00</localTime>\n'
        '<timeZone>CST-4:00:00</timeZone>\n'
        '</Time>\n'
    ),
    'std-cgi.com (Site B NVRs)': (
        '<?xml version="1.0" encoding="UTF-8" ?>'
        '<Time version="1.0" xmlns="http://www.std-cgi.com/ver20/XMLSchema">'
        '<timeMode>manual</timeMode>'
        '<localTime>1970-01-02T03:04:05+04:00</localTime>'
        '<timeZone>CST-4:00:00</timeZone>'
        '</Time>'
    ),
    'hikvision.com (Site C)': (
        '<?xml version="1.0" encoding="UTF-8" ?>'
        '<Time version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">'
        '<timeMode>manual</timeMode>'
        '<localTime>2026-05-29T15:16:24+04:00</localTime>'
        '<timeZone>CST-4:00:00</timeZone>'
        '</Time>'
    ),
}


def capture_ns_version(xml_text):
    """Mirror of HTTPAPIDevice._xml_raw's namespace-capture logic (pure part)."""
    root = ET.fromstring(xml_text)
    ns_uri = root.tag[1:root.tag.index('}')] if root.tag.startswith('{') else None
    version = root.attrib.get('version')
    for el in root.iter():
        if isinstance(el.tag, str) and '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]
    tz = root.find('.//timeZone')
    return ns_uri, version, (tz.text.strip() if tz is not None and tz.text else None)


def run():
    passed = 0
    for label, xml_text in FIXTURES.items():
        ns, ver, tz = capture_ns_version(xml_text)
        expected_ns = {
            'isapi.org v2.0 (Site A time endpoint)': 'http://www.isapi.org/ver20/XMLSchema',
            'std-cgi.com (Site B NVRs)': 'http://www.std-cgi.com/ver20/XMLSchema',
            'hikvision.com (Site C)': 'http://www.hikvision.com/ver20/XMLSchema',
        }[label]
        assert ns == expected_ns, f"{label}: ns capture wrong: {ns}"
        assert tz == 'CST-4:00:00', f"{label}: timezone capture wrong: {tz}"

        ntp_body = cf.build_ntp_server_body(ns, ver, 1, '10.66.66.1', 'ipaddress', 123, 60)
        time_body = cf.build_time_mode_body(ns, ver, tz)

        # Echoed namespace must match the device's own — never hardcoded.
        assert f'xmlns="{ns}"' in ntp_body, f"{label}: ntp body wrong ns"
        assert f'xmlns="{ns}"' in time_body, f"{label}: time body wrong ns"
        if ver:
            assert f'version="{ver}"' in time_body, f"{label}: time body wrong version"
        # The cardinal safety invariant: NEVER set the time directly.
        assert 'localTime' not in time_body, f"{label}: LOCALTIME LEAKED INTO WRITE BODY!"
        # NTP body essentials.
        assert '<timeMode>NTP</timeMode>' in time_body
        assert '<synchronizeInterval>60</synchronizeInterval>' in ntp_body
        assert '<ipAddress>10.66.66.1</ipAddress>' in ntp_body
        assert f'<timeZone>{tz}</timeZone>' in time_body
        # Both must be well-formed XML.
        ET.fromstring(ntp_body)
        ET.fromstring(time_body)

        print(f"  ✓ {label}")
        passed += 1

    # hostname addressing variant
    hb = cf.build_ntp_server_body('http://www.isapi.org/ver20/XMLSchema', '2.0',
                                  2, 'ge.pool.ntp.org', 'hostname', 123, 60)
    assert '<hostName>ge.pool.ntp.org</hostName>' in hb
    assert '<addressingFormatType>hostname</addressingFormatType>' in hb
    ET.fromstring(hb)
    print("  ✓ hostname addressing variant")
    passed += 1

    # RESTORE body safety (regression guard for the partial-write rollback bug):
    # the restore must echo the namespace, keep the prior timeMode, and NEVER
    # carry <localTime> (which would step the clock on a live recorder).
    ns = 'http://www.std-cgi.com/ver20/XMLSchema'
    for mode in ('manual', 'NTP'):
        rb = cf.build_time_body(ns, '1.0', mode,
                                'CST-4:00:00DST01:00:00,M4.1.0/21:00:00,M10.5.0/02:00:00')
        assert 'localTime' not in rb, f"RESTORE BODY LEAKED localTime (mode={mode})"
        assert f'xmlns="{ns}"' in rb, "restore body missing namespace"
        assert f'<timeMode>{mode}</timeMode>' in rb
        ET.fromstring(rb)
    print("  ✓ restore body: namespaced, prior mode, NEVER localTime")
    passed += 1

    # DST strip → Georgia UTC+4 no-DST, idempotent.
    assert cf.strip_dst('CST-4:00:00DST01:00:00,M4.1.0/21:00:00,M10.5.0/02:00:00') == 'CST-4:00:00'
    assert cf.strip_dst('CST-4:00:00') == 'CST-4:00:00'
    assert cf.strip_dst('') == ''
    tzb = cf.build_time_body(ns, '1.0', 'NTP', cf.strip_dst('CST-4:00:00DST01:00:00,M4.1.0/X'))
    assert '<timeZone>CST-4:00:00</timeZone>' in tzb and 'DST' not in tzb and 'localTime' not in tzb
    print("  ✓ strip_dst → CST-4:00:00 + timezone-fix body has no DST / no localTime")
    passed += 1

    print(f"\nAll {passed} clock-fix builder tests passed.")


if __name__ == '__main__':
    run()
