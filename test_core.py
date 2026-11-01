"""
Testes básicos do CyberSec Toolkit.
Execute com: python -m pytest tests/ -v
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def test_compute_hash():
    """Testa cálculo de hash SHA-256."""
    from core.utils import compute_hash

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"CyberSec Toolkit Test")
        tmp_path = f.name

    result = compute_hash(tmp_path, "sha256")
    assert len(result) == 64
    assert result.isalnum()
    os.unlink(tmp_path)


def test_malware_detector_eicar():
    """Testa detecção do arquivo EICAR (hash de teste padrão)."""
    from core.malware_detector import MalwareDetector

    detector = MalwareDetector()
    # Hash MD5 do EICAR test file
    result = detector.check_hash("44d88612fea8a8f36de82e1278abb02f")
    assert result is not None
    assert "EICAR" in result


def test_double_extension_detection():
    """Testa detecção de extensão dupla."""
    from core.malware_detector import MalwareDetector

    detector = MalwareDetector()
    assert detector.check_double_extension("documento.pdf.exe") is True
    assert detector.check_double_extension("arquivo.txt") is False
    assert detector.check_double_extension("relatorio.docx.bat") is True


def test_entropy_calculation():
    """Testa cálculo de entropia."""
    from core.malware_detector import MalwareDetector

    detector = MalwareDetector()

    # Arquivo com conteúdo uniforme tem entropia baixa
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"A" * 1000)
        tmp_low = f.name

    # Arquivo com conteúdo aleatório tem entropia alta
    import os as _os
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(_os.urandom(1000))
        tmp_high = f.name

    entropy_low = detector.compute_entropy(tmp_low)
    entropy_high = detector.compute_entropy(tmp_high)

    assert entropy_low < entropy_high

    _os.unlink(tmp_low)
    _os.unlink(tmp_high)


def test_suspicious_string_detection():
    """Testa detecção de strings suspeitas."""
    from core.malware_detector import MalwareDetector
    import tempfile

    detector = MalwareDetector()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as f:
        f.write(b"import base64\neval(base64.b64decode('aW1wb3J0IG9z'))\n")
        tmp_path = f.name

    findings = detector.check_strings(tmp_path)
    assert len(findings) > 0
    os.unlink(tmp_path)


def test_high_risk_extension():
    """Testa detecção de extensões de alto risco."""
    from core.malware_detector import MalwareDetector

    d = MalwareDetector()
    assert d.check_high_risk_extension("virus.exe") is True
    assert d.check_high_risk_extension("script.ps1") is True
    assert d.check_high_risk_extension("documento.pdf") is False
    assert d.check_high_risk_extension("imagem.jpg") is False


if __name__ == "__main__":
    test_compute_hash()
    test_malware_detector_eicar()
    test_double_extension_detection()
    test_entropy_calculation()
    test_suspicious_string_detection()
    test_high_risk_extension()
    print("\n✔ Todos os testes passaram!")
