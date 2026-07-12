"""P3 (weakness-class evidence model) — crypto rule pack (data/crypto-checks.yaml)
and the path-traversal / XXE additions (INJ-004/005 in source-auth-checks.yaml),
both run through the existing source_auth_scanner engine."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import source_auth_scanner as S  # noqa: E402

CRYPTO = REPO_ROOT / "data" / "crypto-checks.yaml"
SOURCE_AUTH = REPO_ROOT / "data" / "source-auth-checks.yaml"


def _write(tmp_path: Path, name: str, body: str) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


def _crypto_ids(tmp_path: Path) -> set[str]:
    findings = S.scan_repo(tmp_path, S.load_checks(CRYPTO))
    return {f.check_id for f in findings}


def _inj_ids(tmp_path: Path) -> set[str]:
    findings = S.scan_repo(tmp_path, S.load_checks(SOURCE_AUTH))
    return {f.check_id for f in findings if f.check_id.startswith("INJ-")}


# --- crypto pack ------------------------------------------------------------


def test_md5_hash_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "crypto.createHash('md5').update(pw).digest('hex')\n")
    assert "CRYPTO-001" in _crypto_ids(tmp_path)


def test_md5_for_etag_suppressed(tmp_path: Path) -> None:
    # counter-pattern: non-security hashing must not fire.
    _write(tmp_path, "a.js", "const etag = crypto.createHash('md5').update(body) // cache etag\n")
    assert "CRYPTO-001" not in _crypto_ids(tmp_path)


def test_math_random_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "const token = 'r' + Math.random()\n")
    assert "CRYPTO-002" in _crypto_ids(tmp_path)


def test_math_random_animation_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "const jitter = Math.random() * 100 // animation delay\n")
    assert "CRYPTO-002" not in _crypto_ids(tmp_path)


def test_low_bcrypt_rounds_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "bcrypt.genSaltSync(8)\nawait bcrypt.hash(pw, 6)\n")
    assert "CRYPTO-003" in _crypto_ids(tmp_path)


def test_adequate_bcrypt_rounds_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "bcrypt.genSaltSync(12)\n")
    assert "CRYPTO-003" not in _crypto_ids(tmp_path)


def test_ecb_mode_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "crypto.createCipheriv('aes-128-ecb', key, null)\n")
    assert "CRYPTO-004" in _crypto_ids(tmp_path)


# --- multi-stack: Java crypto (Phase A) -------------------------------------


def test_java_md5_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "H.java", 'MessageDigest md = MessageDigest.getInstance("MD5");\n')
    assert "CRYPTO-JAVA-001" in _crypto_ids(tmp_path)


def test_java_md5_for_etag_suppressed(tmp_path: Path) -> None:
    _write(tmp_path, "H.java", 'String etag = MessageDigest.getInstance("MD5"); // cache etag\n')
    assert "CRYPTO-JAVA-001" not in _crypto_ids(tmp_path)


def test_java_random_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "T.java", 'String token = "t" + new Random().nextInt();\n')
    assert "CRYPTO-JAVA-002" in _crypto_ids(tmp_path)


def test_java_securerandom_token_suppressed(tmp_path: Path) -> None:
    _write(tmp_path, "T.java", 'byte[] token = new byte[32]; new SecureRandom().nextBytes(token);\n')
    assert "CRYPTO-JAVA-002" not in _crypto_ids(tmp_path)


def test_java_ecb_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "C.java", 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n')
    assert "CRYPTO-JAVA-003" in _crypto_ids(tmp_path)


# --- multi-stack: Python crypto (Phase A) -----------------------------------


def test_python_md5_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "h.py", "digest = hashlib.md5(password.encode()).hexdigest()\n")
    assert "CRYPTO-PY-001" in _crypto_ids(tmp_path)


def test_python_md5_usedforsecurity_false_suppressed(tmp_path: Path) -> None:
    _write(tmp_path, "h.py", "key = hashlib.md5(data, usedforsecurity=False).hexdigest()\n")
    assert "CRYPTO-PY-001" not in _crypto_ids(tmp_path)


def test_python_random_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "t.py", "token = str(random.randint(1000, 9999))\n")
    assert "CRYPTO-PY-002" in _crypto_ids(tmp_path)


def test_python_secrets_token_suppressed(tmp_path: Path) -> None:
    _write(tmp_path, "t.py", "token = secrets.token_urlsafe(32)  # not random.random\n")
    assert "CRYPTO-PY-002" not in _crypto_ids(tmp_path)


def test_java_python_crypto_fold_into_one_weakness(tmp_path: Path) -> None:
    # A Java and a Python weak-crypto sink both fold into ONE weak_crypto
    # weakness via _PRACTICE_TIER_CWES — no per-language peer explosion.
    import merge_threats as mt  # noqa: E402

    threats = [
        {"t_id": "T-001", "source": "source-scan", "cwe": "CWE-328", "component_id": "svc",
         "risk": "Medium", "evidence": {"file": "H.java", "line": 3}},
        {"t_id": "T-002", "source": "source-scan", "cwe": "CWE-330", "component_id": "svc",
         "risk": "High", "evidence": {"file": "t.py", "line": 5}},
    ]
    w = mt.build_weakness_register(threats, [], {})
    assert len(w) == 1
    assert w[0]["weakness_class"] == "weak_crypto"
    assert len(w[0]["observable_backing"]["practice_evidence"]) == 2


# --- multi-stack: Java / Python injection (Phase A) -------------------------


def test_java_sqli_concat_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "R.java",
           'Query q = em.createQuery("SELECT u FROM User u WHERE u.name=\'" + name + "\'");\n')
    assert "INJ-JAVA-001" in _inj_ids(tmp_path)


def test_java_sqli_parameterized_suppressed(tmp_path: Path) -> None:
    _write(tmp_path, "R.java",
           'Query q = em.createQuery("SELECT u FROM User u WHERE u.name=:n").setParameter("n", name);\n')
    assert "INJ-JAVA-001" not in _inj_ids(tmp_path)


def test_java_command_injection_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "C.java", 'Runtime.getRuntime().exec("ping " + host);\n')
    assert "INJ-JAVA-002" in _inj_ids(tmp_path)


def test_python_sqli_fstring_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "r.py", 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n')
    assert "INJ-PY-001" in _inj_ids(tmp_path)


def test_python_sqli_parameterized_suppressed(tmp_path: Path) -> None:
    _write(tmp_path, "r.py", 'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))\n')
    assert "INJ-PY-001" not in _inj_ids(tmp_path)


def test_python_command_injection_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "c.py", "os.system('ping ' + host)\n")
    assert "INJ-PY-002" in _inj_ids(tmp_path)


def test_java_ssrf_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "S.java", 'restTemplate.getForObject("http://" + host + "/api", String.class);\n')
    assert "INJ-JAVA-003" in _inj_ids(tmp_path)


def test_java_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "P.java", 'File f = new File("/data/" + name);\n')
    assert "INJ-JAVA-004" in _inj_ids(tmp_path)


def test_java_path_canonicalized_suppressed(tmp_path: Path) -> None:
    _write(tmp_path, "P.java", 'File f = new File("/data/" + name); f.getCanonicalPath();\n')
    assert "INJ-JAVA-004" not in _inj_ids(tmp_path)


def test_python_ssrf_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "s.py", 'requests.get(f"http://{host}/api")\n')
    assert "INJ-PY-003" in _inj_ids(tmp_path)


def test_python_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "p.py", 'open("/data/" + name).read()\n')
    assert "INJ-PY-004" in _inj_ids(tmp_path)


# --- multi-stack: Go (Phase B) ----------------------------------------------


def test_go_md5_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "h.go", "h := md5.New()\n")
    assert "CRYPTO-GO-001" in _crypto_ids(tmp_path)


def test_go_math_rand_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "t.go", "token := rand.Intn(9999)\n")
    assert "CRYPTO-GO-002" in _crypto_ids(tmp_path)


def test_go_sqli_sprintf_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "r.go", 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE n=\'%s\'", name))\n')
    assert "INJ-GO-001" in _inj_ids(tmp_path)


def test_go_command_injection_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "c.go", 'exec.Command("sh", "-c", "ping "+host)\n')
    assert "INJ-GO-002" in _inj_ids(tmp_path)


def test_go_ssrf_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "s.go", 'resp, _ := http.Get(fmt.Sprintf("http://%s/api", host))\n')
    assert "INJ-GO-003" in _inj_ids(tmp_path)


def test_go_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "p.go", 'data, _ := os.ReadFile("/data/" + name)\n')
    assert "INJ-GO-004" in _inj_ids(tmp_path)


# --- multi-stack: C#/.NET (Phase B) -----------------------------------------


def test_csharp_md5_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "H.cs", "using (var md5 = MD5.Create()) { }\n")
    assert "CRYPTO-CS-001" in _crypto_ids(tmp_path)


def test_csharp_random_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "T.cs", "var token = new Random().Next().ToString();\n")
    assert "CRYPTO-CS-002" in _crypto_ids(tmp_path)


def test_csharp_sqli_interpolated_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "R.cs", 'ctx.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = \'{name}\'");\n')
    assert "INJ-CS-001" in _inj_ids(tmp_path)


def test_csharp_command_injection_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "C.cs", 'Process.Start("ping " + host);\n')
    assert "INJ-CS-002" in _inj_ids(tmp_path)


def test_csharp_ssrf_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "S.cs", 'var r = await client.GetStringAsync($"http://{host}/api");\n')
    assert "INJ-CS-003" in _inj_ids(tmp_path)


def test_csharp_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "P.cs", 'var txt = File.ReadAllText("/data/" + name);\n')
    assert "INJ-CS-004" in _inj_ids(tmp_path)


# --- multi-stack: PHP (Phase B) ---------------------------------------------


def test_php_md5_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "h.php", "<?php $h = md5($password);\n")
    assert "CRYPTO-PHP-001" in _crypto_ids(tmp_path)


def test_php_mt_rand_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "t.php", "<?php $token = mt_rand(1000, 9999);\n")
    assert "CRYPTO-PHP-002" in _crypto_ids(tmp_path)


def test_php_sqli_superglobal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "r.php", "<?php mysqli_query($c, \"SELECT * FROM u WHERE n='\" . $_GET['n'] . \"'\");\n")
    assert "INJ-PHP-001" in _inj_ids(tmp_path)


def test_php_command_injection_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "c.php", "<?php system('ping ' . $_GET['host']);\n")
    assert "INJ-PHP-002" in _inj_ids(tmp_path)


def test_php_ssrf_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "s.php", "<?php $data = file_get_contents($_GET['url']);\n")
    assert "INJ-PHP-003" in _inj_ids(tmp_path)


def test_php_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "p.php", "<?php readfile('/data/' . $_GET['f']);\n")
    assert "INJ-PHP-004" in _inj_ids(tmp_path)


# --- multi-stack: Ruby / Rails (Phase B) ------------------------------------


def test_ruby_md5_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "h.rb", "digest = Digest::MD5.hexdigest(password)\n")
    assert "CRYPTO-RB-001" in _crypto_ids(tmp_path)


def test_ruby_rand_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "t.rb", "token = rand(9999).to_s\n")
    assert "CRYPTO-RB-002" in _crypto_ids(tmp_path)


def test_ruby_sqli_interpolation_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "r.rb", 'User.where("name = \'#{params[:name]}\'")\n')
    assert "INJ-RB-001" in _inj_ids(tmp_path)


def test_ruby_command_injection_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "c.rb", 'system("ping #{params[:host]}")\n')
    assert "INJ-RB-002" in _inj_ids(tmp_path)


def test_ruby_ssrf_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "s.rb", 'Net::HTTP.get(URI("http://#{host}/api"))\n')
    assert "INJ-RB-003" in _inj_ids(tmp_path)


def test_ruby_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "p.rb", 'File.read("/data/#{params[:f]}")\n')
    assert "INJ-RB-004" in _inj_ids(tmp_path)


# --- multi-stack: Android (Phase C, mobile) ---------------------------------


def _mobile_ids(tmp_path: Path) -> set[str]:
    findings = S.scan_repo(tmp_path, S.load_checks(SOURCE_AUTH))
    return {f.check_id for f in findings}


def test_kotlin_md5_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "H.kt", 'val md = MessageDigest.getInstance("MD5")\n')
    assert "CRYPTO-KT-001" in _crypto_ids(tmp_path)


def test_kotlin_random_token_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "T.kt", 'val token = Random().nextInt(9999).toString()\n')
    assert "CRYPTO-KT-002" in _crypto_ids(tmp_path)


def test_android_sqlite_injection_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "D.kt", 'db.rawQuery("SELECT * FROM u WHERE n=\'" + name + "\'", null)\n')
    assert "MOBILE-AND-001" in _mobile_ids(tmp_path)


def test_android_insecure_storage_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "S.kt", 'prefs.edit().putString("auth_token", token).apply()\n')
    assert "MOBILE-AND-002" in _mobile_ids(tmp_path)


def test_android_encrypted_prefs_suppressed(tmp_path: Path) -> None:
    # Counter is forward/same-line only (scanner window semantics), so the
    # fluent-chained EncryptedSharedPreferences form is what gets suppressed.
    _write(tmp_path, "S.kt",
           'EncryptedSharedPreferences.create(ctx, ...).edit().putString("auth_token", token).apply()\n')
    assert "MOBILE-AND-002" not in _mobile_ids(tmp_path)


def test_android_webview_bridge_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "W.kt", 'webView.addJavascriptInterface(JsBridge(), "Android")\n')
    assert "MOBILE-AND-003" in _mobile_ids(tmp_path)


# --- path traversal / XXE ---------------------------------------------------


def test_path_traversal_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "res.sendFile(path.join(root, req.query.name))\n")
    assert "INJ-004" in _inj_ids(tmp_path)


def test_path_traversal_sanitized_suppressed(tmp_path: Path) -> None:
    # The common safe form canonicalizes inline → counter-pattern suppresses.
    _write(tmp_path, "a.js", "res.sendFile(path.join(root, path.basename(req.query.name)))\n")
    assert "INJ-004" not in _inj_ids(tmp_path)


def test_xxe_noent_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.js", "libxmljs.parseXml(input, { noent: true })\n")
    assert "INJ-005" in _inj_ids(tmp_path)


def test_crypto_cwes_map_to_weak_crypto_class() -> None:
    # The crypto CWEs must land in the weak_crypto weakness cluster so a
    # crypto finding folds under a weak_crypto weakness (P3 verify).
    import weakness_classifier as wc

    for cwe in ("CWE-328", "CWE-330", "CWE-916", "CWE-327"):
        assert wc.classify_cwe(cwe) == "weak_crypto", cwe
    assert wc.classify_cwe("CWE-22") == "injection"
    assert wc.classify_cwe("CWE-611") == "injection"


def test_crypto_findings_fold_under_weak_crypto_weakness() -> None:
    """P3 verify — crypto findings (insecure-practice) fold under one
    weak_crypto weakness rather than standing as confirmed vulns."""
    import merge_threats as mt

    threats = [
        {"t_id": "T-001", "source": "source-scan", "cwe": "CWE-328", "component_id": "auth",
         "risk": "Medium", "evidence": {"file": "auth.js", "line": 1}},
        {"t_id": "T-002", "source": "source-scan", "cwe": "CWE-916", "component_id": "auth",
         "risk": "Medium", "evidence": {"file": "auth.js", "line": 3}},
    ]
    w = mt.build_weakness_register(threats, None)
    assert len(w) == 1
    assert w[0]["weakness_class"] == "weak_crypto"
    assert len(w[0]["observable_backing"]["practice_evidence"]) == 2
    # crypto is a practice, never a confirmed exploit
    assert all(t["evidence_tier"] == "insecure-practice" for t in threats)
