import addon


def test_media_hosts_only():
    for h in ("mmg.whatsapp.net", "media.fhfa1-1.fna.whatsapp.net", "media-lhr6-2.cdn.whatsapp.net", "scontent.whatsapp.net"):
        assert addon._wa_media_host(h)
    for h in ("g.whatsapp.net", "api.whatsapp.net", "v.whatsapp.net", "pps.whatsapp.net", "static.whatsapp.net",
              "media.example.com", "mmg.whatsapp.net.evil.com", "www.whatsapp.com"):
        assert not addon._wa_media_host(h)


def test_flag_file_switches_mode(tmp_path, monkeypatch):
    flag = tmp_path / "wa"
    monkeypatch.setattr(addon, "WA_FLAG", flag)
    addon._wa_state[:] = [0.0, False]
    assert not addon._wa_text_only()
    flag.touch()
    addon._wa_state[0] = 0.0
    assert addon._wa_text_only()
