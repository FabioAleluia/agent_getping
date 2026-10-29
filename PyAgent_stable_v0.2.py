"""Agente Getping: coleta limitada por tempo e payload compatível com v0.0.2."""
import configparser
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import getpass
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import random
import re
import socket
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

import requests

VERSION = "0.0.4"
PASTA_BASE = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
CAMINHO_CONFIG = PASTA_BASE / "config.ini"
LOG = logging.getLogger("getping.agent")


def criar_config_padrao():
    """Cria somente um modelo; nunca inicia envios para um servidor embutido."""
    CAMINHO_CONFIG.write_text(
        "[servidor]\nurl = http://SEU_IP_SERVIDOR:5000/informacoes_agent\n"
        "token = SEU_TOKEN_DE_AGENTE_AQUI\nintervalo = 20\n\n"
        "[rede]\nip_teste_wan = 8.8.8.8\n", encoding="utf-8")


def carregar_config():
    config = configparser.ConfigParser(interpolation=None)
    try:
        with open(CAMINHO_CONFIG, encoding="utf-8-sig") as arquivo:
            config.read_file(arquivo)
        url = config.get("servidor", "url").strip()
        token = config.get("servidor", "token").strip()
        intervalo = config.getint("servidor", "intervalo")
        wan = config.get("rede", "ip_teste_wan").strip()
        partes = urlsplit(url)
        # Acessar .port também valida portas malformadas.
        porta = partes.port
        if (partes.scheme not in ("http", "https") or not partes.hostname
                or partes.username is not None or partes.password is not None
                or partes.fragment or (porta is not None and not 1 <= porta <= 65535)
                or "SEU_IP_SERVIDOR" in url or any(c.isspace() for c in url)):
            raise ValueError("URL HTTP/HTTPS inválida ou ainda não configurada")
        if (not token or token.upper() in ("TROQUE_PELO_TOKEN_REAL", "SEU_TOKEN_DE_AGENTE_AQUI")
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError("token ausente, inválido ou de exemplo")
        if not 5 <= intervalo <= 86400:
            raise ValueError("intervalo deve estar entre 5 e 86400 segundos")
        endereco = ipaddress.ip_address(wan)
        if endereco.version != 4 or endereco.is_unspecified or endereco.is_multicast:
            raise ValueError("ip_teste_wan deve ser um IPv4 unicast")
        resultado = {"servidor": url, "token": token, "intervalo": intervalo, "ip_teste_wan": wan}
        ca = config.get("servidor", "certificado_ca", fallback="").strip()
        if ca:
            caminho_ca = Path(ca)
            if not caminho_ca.is_absolute():
                caminho_ca = Path(CAMINHO_CONFIG).parent / caminho_ca
            if not caminho_ca.is_file():
                raise ValueError("Arquivo de CA não encontrado")
            resultado["certificado_ca"] = str(caminho_ca.resolve())
        return resultado
    except (OSError, configparser.Error, ValueError) as erro:
        # Não imprimir o conteúdo da configuração: pode conter credenciais.
        raise ValueError("Configuração inválida. Confira URL, token, intervalo (5–86400) "
                         "ip_teste_wan IPv4 e certificado_ca (se definido) em config.ini.") from erro


def configurar_logs():
    LOG.setLevel(logging.INFO)
    formato = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formato)
    LOG.addHandler(console)
    try:
        arquivo = RotatingFileHandler(PASTA_BASE / "agent.log", maxBytes=2_000_000,
                                      backupCount=3, encoding="utf-8")
        arquivo.setFormatter(formato)
        LOG.addHandler(arquivo)
    except OSError:
        LOG.warning("Log em arquivo indisponível; usando apenas console.")


def executar(cmd, timeout=5):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, check=True,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                          if platform.system() == "Windows" else 0).stdout.strip()


def powershell(comando):
    return executar(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                     "-Command", "$ErrorActionPreference='Stop'; "
                     "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + comando], 10)


def seguro(nome, funcao, padrao="Desconhecido"):
    try:
        return funcao()
    except Exception as erro:
        LOG.warning("Falha no coletor %s (%s).", nome, type(erro).__name__)
        return padrao


def get_hostname():
    return socket.gethostname()


def get_user_logon():
    if platform.system() != "Windows":
        # A limitação em serviços Linux é documentada no README.
        return getpass.getuser()

    class Sessao(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("pWinStationName", wintypes.LPWSTR),
                    ("State", ctypes.c_int)]

    wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WTSGetActiveConsoleSessionId.argtypes = []
    kernel.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    wts.WTSEnumerateSessionsW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                        ctypes.POINTER(ctypes.POINTER(Sessao)), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSEnumerateSessionsW.restype = wintypes.BOOL
    wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                                              ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    wts.WTSFreeMemory.restype = None
    sessoes = ctypes.POINTER(Sessao)()
    quantidade = wintypes.DWORD()
    if not wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(sessoes), ctypes.byref(quantidade)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        ativos = [sessoes[i].SessionId for i in range(quantidade.value) if sessoes[i].State == 0]
        console = kernel.WTSGetActiveConsoleSessionId()
        ativos.sort(key=lambda sid: (sid != console, sid))
        for sid in ativos:
            buffer = wintypes.LPWSTR()
            tamanho = wintypes.DWORD()
            try:
                sucesso = wts.WTSQuerySessionInformationW(None, sid, 5, ctypes.byref(buffer), ctypes.byref(tamanho))
                if sucesso and buffer.value:
                    return buffer.value
            finally:
                if buffer:
                    wts.WTSFreeMemory(buffer)
        return "Nenhum usuário logado"
    finally:
        if sessoes:
            wts.WTSFreeMemory(sessoes)


def get_system_operacional():
    if platform.system() != "Windows":
        return f"{platform.system()} {platform.release()}"
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        def valor(nome, padrao="N/A"):
            try:
                return winreg.QueryValueEx(key, nome)[0]
            except FileNotFoundError:
                return padrao
        produto = valor("ProductName", "Windows")
        build = valor("CurrentBuildNumber", "0")
        versao = valor("DisplayVersion", valor("ReleaseId"))
        if valor("InstallationType", "") == "Client" and int(build) >= 22000:
            produto = produto.replace("Windows 10", "Windows 11")
        return f"{produto} {versao} (Build {build})"


def identidade_valida(valor):
    if not isinstance(valor, str):
        return False
    try:
        numero = uuid.UUID(valor).int
        return numero not in (0, (1 << 128) - 1)
    except ValueError:
        return False


def get_machine_uuid():
    """Preserva formato/caixa do ID existente; nunca troca por MAC após falha WMI."""
    caminho = PASTA_BASE / "machine_identity.json"
    if caminho.exists():
        estado = json.loads(caminho.read_text(encoding="utf-8"))
        if not identidade_valida(estado.get("machine_uuid")):
            raise ValueError("Identidade persistida inválida; requer intervenção")
        return estado["machine_uuid"]
    if platform.system() == "Windows":
        # Falha WMI impede esta amostra; não cria uma identidade alternativa silenciosa.
        identidade = powershell("(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID").strip()
    elif platform.system() == "Linux":
        identidade = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    else:
        raise RuntimeError("Sistema sem política de identidade definida")
    if not identidade_valida(identidade):
        raise ValueError("Identidade de hardware ausente ou inválida")
    temporario = caminho.with_suffix(".tmp")
    try:
        with open(temporario, "w", encoding="utf-8") as arquivo:
            json.dump({"machine_uuid": identidade}, arquivo)
        os.replace(temporario, caminho)
    finally:
        temporario.unlink(missing_ok=True)
    return identidade


def get_rede(alvo):
    """Retorna IP e gateway da mesma rota IPv4 até o destino de diagnóstico."""
    ipaddress.IPv4Address(alvo)  # Garante que a interpolação no PowerShell é um IP.
    if platform.system() == "Windows":
        dados = json.loads(powershell(
            f"$r=@(Find-NetRoute -RemoteIPAddress '{alvo}'); "
            "$ip=$r | Where-Object { $_.PSObject.Properties['IPAddress'] } | Select-Object -First 1; "
            "$rt=$r | Where-Object { $_.PSObject.Properties['NextHop'] } | Select-Object -First 1; "
            "if (!$ip -or !$rt) { throw 'Rota indisponivel' }; "
            "@{ip=$ip.IPAddress;gateway=$rt.NextHop} | ConvertTo-Json -Compress"))
    else:
        rotas = json.loads(executar(["ip", "-j", "-4", "route", "get", alvo]))
        rota = rotas[0]
        dados = {"ip": rota.get("prefsrc", rota.get("src")), "gateway": rota.get("gateway")}
    ip = str(ipaddress.IPv4Address(dados["ip"]))
    gateway = dados.get("gateway")
    if gateway and gateway != "0.0.0.0":
        gateway = str(ipaddress.IPv4Address(gateway))
    else:
        gateway = None
    return ip, gateway


def fazer_ping(ping_ip):
    if not ping_ip:
        return False, None
    try:
        endereco = ipaddress.ip_address(ping_ip)
        windows = platform.system() == "Windows"
        cmd = ["ping", "-n" if windows else "-c", "1",
               "-w" if windows else "-W", "1000" if windows else "1"]
        if endereco.version == 6:
            cmd.append("-6")
        cmd.append(str(endereco))
        saida = executar(cmd, timeout=3)
        match = re.search(r"(?:time|tempo)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*ms", saida, re.I)
        if not match:
            LOG.warning("Ping sem resposta de latência reconhecida.")
            return False, None
        # Mantém inteiro ou null como no payload anterior. <1ms é reportado como 1ms.
        latencia = float(match.group(2).replace(",", "."))
        return True, max(1, round(latencia))
    except (OSError, ValueError, subprocess.SubprocessError):
        return False, None


class Agente:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {config['token']}"})
        if config.get("certificado_ca"):
            self.session.verify = config["certificado_ca"]
        self.identidade = None
        self.sistema = None
        self.sistema_atualizado = 0
        self.falhas = 0
        self.boot_id = str(uuid.uuid4())
        self.sequencia = 0

    def coletar(self):
        # Não enviar amostras sem uma identidade confiável.
        if self.identidade is None:
            try:
                self.identidade = get_machine_uuid()
            except Exception:
                LOG.error("Identidade indisponível: confira WMI/machine-id, machine_identity.json "
                          "e permissão de escrita no diretório. Amostra não enviada.")
                raise
        agora = time.monotonic()
        if self.sistema is None or agora - self.sistema_atualizado >= 3600:
            sistema = seguro("sistema operacional", get_system_operacional, None)
            if sistema is not None:
                self.sistema = sistema
                self.sistema_atualizado = agora
        ip, gateway = seguro("rota IPv4", lambda: get_rede(self.config["ip_teste_wan"]),
                             ("Desconhecido", None))
        lan, ms_lan = fazer_ping(gateway)
        wan, ms_wan = fazer_ping(self.config["ip_teste_wan"])
        self.sequencia += 1
        return {"hostname": seguro("hostname", get_hostname),
                "user_logon": seguro("usuário", get_user_logon),
                "ip_local": ip, "system_operacional": self.sistema or "Desconhecido",
                "machine_uuid": self.identidade, "status_lan": lan, "time_ms_lan": ms_lan,
                "status_wan": wan, "time_ms_wan": ms_wan,
                "medido_em": datetime.now(timezone.utc).isoformat(),
                "boot_id": self.boot_id, "sequencia": self.sequencia}

    def enviar(self, dados):
        try:
            # Sem redirecionamentos: um login HTML não pode ser interpretado como aceite.
            with self.session.post(self.config["servidor"], json=dados,
                                   timeout=(3.05, 5), allow_redirects=False,
                                   **({"verify": self.config["certificado_ca"]}
                                      if self.config.get("certificado_ca") else {})) as resposta:
                codigo = resposta.status_code
                try:
                    conteudo = resposta.json()
                except ValueError:
                    conteudo = {}
                if not isinstance(conteudo, dict):
                    conteudo = {}
                if 200 <= codigo < 300 and conteudo.get("aceito") is False:
                    LOG.warning("Servidor recebeu a requisição, mas descartou a medição "
                                "(aceito=false). Confira relógio UTC, sequência e instâncias duplicadas.")
                    return False, 0
                if 200 <= codigo < 300:
                    LOG.info("Telemetria enviada (HTTP %s).", codigo)
                    return True, 0
                if codigo in (400, 401, 403):
                    diagnosticos = {
                        "Host legado exige vinculação administrativa.":
                            "Host já cadastrado sem vínculo: um administrador deve vincular o token ao UUID no Getping (bind-agent).",
                        "Token vinculado a outro dispositivo.":
                            "Token pertence a outro equipamento. Use uma credencial exclusiva para esta máquina.",
                        "Token revogado.": "Token revogado no servidor. Configure uma credencial ativa.",
                        "Acesso negado": "Token inválido ou inativo. Confira a credencial no Getping.",
                        "Não autorizado": "Cabeçalho de autenticação ausente; confira o proxy e o token.",
                        "Formato inválido": "Formato da autenticação recusado; confira o proxy e o token.",
                        "Este dispositivo deve continuar enviando boot_id e sequencia.":
                            "Servidor exige protocolo com boot_id e sequencia. Execute a versão atual do agente.",
                        "Medição fora da janela de atualidade.":
                            "Relógio fora da janela permitida. Sincronize data/hora da máquina e do servidor.",
                    }
                    motivo = conteudo.get("erro")
                    detalhe = diagnosticos.get(motivo) if isinstance(motivo, str) else None
                    LOG.error("Envio recusado (HTTP %s). %s", codigo, detalhe or
                              "Confira configuração, licença, identidade e vinculação do token no Getping.")
                    return False, 300 if codigo in (401, 403) else 0
                if codigo in (429, 503):
                    LOG.warning("Servidor limitando envios ou indisponível (HTTP %s).", codigo)
                    return False, retry_after(resposta.headers.get("Retry-After"))
                LOG.warning("Envio recusado (HTTP %s).", codigo)
        except requests.exceptions.SSLError:
            LOG.error("Falha TLS (SSLError). Confira HTTPS na porta correta, o IP/nome do "
                      "certificado e a CA confiável. Configure certificado_ca com o certificado "
                      "público da CA do Getping; não use HTTPS na porta HTTP 5000.")
        except requests.exceptions.ConnectionError:
            LOG.warning("Falha de conexão (ConnectionError). Confira endereço, porta, firewall "
                        "e serviço. Na instalação HTTPS do Getping, use a porta 443; "
                        "o backend 127.0.0.1:5000 não aceita clientes remotos.")
        except requests.RequestException as erro:
            # Mensagem da exceção/response pode incluir URL, token ou dados sensíveis.
            LOG.warning("Falha de comunicação (%s).", type(erro).__name__)
        return False, 0

    def ciclo(self):
        try:
            sucesso, espera = self.enviar(self.coletar())
        except Exception as erro:
            LOG.error("Ciclo incompleto (%s); nova tentativa será agendada.", type(erro).__name__)
            sucesso, espera = False, 0
        if sucesso:
            self.falhas = 0
            return self.config["intervalo"]
        self.falhas = min(self.falhas + 1, 10)
        base = min(300, self.config["intervalo"] * 2 ** (self.falhas - 1))
        atraso = max(self.config["intervalo"], espera, base + random.uniform(0, base * .2))
        LOG.warning("Nova tentativa em %.1f segundos.", atraso)
        return atraso

    def close(self):
        self.session.close()


def retry_after(valor):
    try:
        if valor is None:
            return 0
        try:
            segundos = float(int(valor))
        except ValueError:
            data = parsedate_to_datetime(valor)
            segundos = (data - datetime.now(timezone.utc)).total_seconds()
        return min(86400, max(0, segundos))
    except (TypeError, ValueError, OverflowError):
        return 0


def start_pyagent():
    configurar_logs()
    try:
        config = carregar_config()
    except ValueError as erro:
        LOG.error("%s", erro)
        return 2
    if urlsplit(config["servidor"]).scheme == "http":
        LOG.warning("HTTP configurado: token e telemetria sem criptografia. Migre para HTTPS quando disponível.")
    LOG.info("Agente %s iniciado.", VERSION)
    agente = Agente(config)
    try:
        time.sleep(random.uniform(0, min(config["intervalo"], 10)))
        while True:
            inicio = time.monotonic()
            periodo = agente.ciclo()
            # Não dispara rajadas para compensar ciclos demorados.
            time.sleep(periodo if agente.falhas else max(1, inicio + periodo - time.monotonic()))
    except KeyboardInterrupt:
        LOG.info("Agente encerrado.")
    finally:
        agente.close()
    return 0


if __name__ == "__main__":
    sys.exit(start_pyagent())
