"""Regressões sem comandos do sistema nem chamadas ao servidor real."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

spec = importlib.util.spec_from_file_location("agent", Path(__file__).resolve().parents[1] / "PyAgent_stable_v0.2.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
CONFIG = {"servidor": "http://example.invalid/informacoes_agent", "token": "test-token",
          "intervalo": 20, "ip_teste_wan": "8.8.8.8"}
IDENTIDADE = "12345678-1234-4234-8234-123456789abc"


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.arquivo = Path(self.temp.name) / "config.ini"
        self.patch = patch.object(agent, "CAMINHO_CONFIG", self.arquivo)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def escrever(self, intervalo="20", url=CONFIG["servidor"], token="abc%123", wan="8.8.8.8"):
        self.arquivo.write_text(f"[servidor]\nurl={url}\ntoken={token}\nintervalo={intervalo}\n"
                                f"[rede]\nip_teste_wan={wan}\n", encoding="utf-8")

    def test_config_existente_e_token_com_percentual(self):
        self.escrever()
        self.assertEqual(agent.carregar_config()["token"], "abc%123")

    def test_intervalos_invalidos(self):
        for intervalo in ("abc", "-1", "0", "4", "86401"):
            with self.subTest(intervalo=intervalo):
                self.escrever(intervalo=intervalo)
                with self.assertRaises(ValueError):
                    agent.carregar_config()

    def test_url_token_e_alvo_invalidos(self):
        for kwargs in ({"url": "ftp://example.invalid"}, {"url": "http://a:99999"},
                       {"url": "http://user:password@example.invalid"},
                       {"url": "http://SEU_IP_SERVIDOR:5000/informacoes_agent"},
                       {"token": "SEU_TOKEN_DE_AGENTE_AQUI"}, {"token": ""},
                       {"wan": "8.8.8.8; whoami"}, {"wan": "::1"}):
            with self.subTest(kwargs=kwargs):
                self.escrever(**kwargs)
                with self.assertRaises(ValueError):
                    agent.carregar_config()

    def test_ca_relativa_e_arquivo_ausente(self):
        self.escrever()
        texto = self.arquivo.read_text().replace("[servidor]", "[servidor]\ncertificado_ca=ca.crt")
        self.arquivo.write_text(texto)
        with self.assertRaises(ValueError):
            agent.carregar_config()
        ca = self.arquivo.parent / "ca.crt"
        ca.write_text("fixture")
        self.assertEqual(agent.carregar_config()["certificado_ca"], str(ca.resolve()))

    def test_arquivo_ausente_nao_envia_para_fallback(self):
        with self.assertRaises(ValueError):
            agent.carregar_config()
        self.assertFalse(self.arquivo.exists())


class ColetaTests(unittest.TestCase):
    def test_ping_nao_aceita_destino_inacessivel(self):
        with patch.object(agent, "executar", return_value="Host de destino inacessível."):
            self.assertEqual(agent.fazer_ping("8.8.8.8"), (False, None))

    def test_ping_localizado_e_tipo_inteiro(self):
        for saida, esperado in (("tempo<1ms", 1), ("time=0.450 ms", 1),
                                ("tempo=12ms", 12), ("time=1,8 ms", 2)):
            with self.subTest(saida=saida), patch.object(agent, "executar", return_value=saida):
                self.assertEqual(agent.fazer_ping("8.8.8.8"), (True, esperado))

    def test_ping_timeout_e_comando_ausente(self):
        for erro in (subprocess.TimeoutExpired("ping", 3), FileNotFoundError()):
            with patch.object(agent, "executar", side_effect=erro):
                self.assertEqual(agent.fazer_ping("8.8.8.8"), (False, None))

    def test_execucao_limitada_sem_shell(self):
        with patch.object(agent.subprocess, "run", return_value=Mock(stdout="ok")) as run:
            self.assertEqual(agent.executar(["test"], timeout=7), "ok")
            self.assertEqual(run.call_args.kwargs["timeout"], 7)
            self.assertTrue(run.call_args.kwargs["check"])
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_rota_windows_ip_e_gateway_mesmo_resultado(self):
        with patch.object(agent.platform, "system", return_value="Windows"), patch.object(
                agent, "powershell", return_value='{"ip":"10.8.0.2","gateway":"10.8.0.1"}'):
            self.assertEqual(agent.get_rede("8.8.8.8"), ("10.8.0.2", "10.8.0.1"))

    def test_rota_linux_estruturada(self):
        with patch.object(agent.platform, "system", return_value="Linux"), patch.object(
                agent, "executar", return_value='[{"prefsrc":"192.168.1.2","gateway":"192.168.1.1"}]'):
            self.assertEqual(agent.get_rede("8.8.8.8"), ("192.168.1.2", "192.168.1.1"))

    def test_rota_direta_sem_gateway(self):
        with patch.object(agent.platform, "system", return_value="Windows"), patch.object(
                agent, "powershell", return_value='{"ip":"10.0.0.2","gateway":"0.0.0.0"}'):
            self.assertEqual(agent.get_rede("8.8.8.8"), ("10.0.0.2", None))

    def test_identidade_persistida_sobrevive_falha_wmi(self):
        with tempfile.TemporaryDirectory() as pasta, patch.object(agent, "PASTA_BASE", Path(pasta)), \
                patch.object(agent.platform, "system", return_value="Windows"), \
                patch.object(agent, "powershell", return_value=IDENTIDADE) as ps:
            self.assertEqual(agent.get_machine_uuid(), IDENTIDADE)
            ps.side_effect = subprocess.TimeoutExpired("powershell", 10)
            self.assertEqual(agent.get_machine_uuid(), IDENTIDADE)
            self.assertEqual(ps.call_count, 1)

    def test_falha_wmi_nao_cria_identidade_alternativa(self):
        with tempfile.TemporaryDirectory() as pasta, patch.object(agent, "PASTA_BASE", Path(pasta)), \
                patch.object(agent.platform, "system", return_value="Windows"), \
                patch.object(agent, "powershell", side_effect=subprocess.TimeoutExpired("powershell", 10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                agent.get_machine_uuid()
            self.assertFalse((Path(pasta) / "machine_identity.json").exists())

    def test_identidade_corrompida_nao_e_substituida(self):
        with tempfile.TemporaryDirectory() as pasta, patch.object(agent, "PASTA_BASE", Path(pasta)):
            caminho = Path(pasta) / "machine_identity.json"
            caminho.write_text('{"machine_uuid":"UNKNOWN-UUID"}')
            with self.assertRaises(ValueError):
                agent.get_machine_uuid()
            self.assertIn("UNKNOWN-UUID", caminho.read_text())

    def test_uuid_zero_rejeitado(self):
        self.assertFalse(agent.identidade_valida("00000000-0000-0000-0000-000000000000"))
        self.assertFalse(agent.identidade_valida("ffffffff-ffff-ffff-ffff-ffffffffffff"))


class TransporteTests(unittest.TestCase):
    def setUp(self):
        self.agente = agent.Agente(CONFIG)
        self.addCleanup(self.agente.close)

    def resposta(self, codigo, cabecalhos=None):
        resposta = requests.Response()
        resposta.status_code = codigo
        resposta._content = b""
        resposta._content_consumed = True
        resposta.headers.update(cabecalhos or {})
        return resposta

    def test_payload_e_autenticacao_usando_requests_real_sem_rede(self):
        dono = self
        preparados = []
        class Adaptador(requests.adapters.BaseAdapter):
            def send(self, request, **kwargs):
                preparados.append(request)
                return dono.resposta(200)
            def close(self):
                pass
        self.agente.session.mount("http://", Adaptador())
        with patch.object(agent, "get_machine_uuid", return_value=IDENTIDADE), \
                patch.object(agent, "get_system_operacional", return_value="Windows 11"), \
                patch.object(agent, "get_rede", return_value=("10.0.0.2", "10.0.0.1")), \
                patch.object(agent, "get_user_logon", return_value="usuario"), \
                patch.object(agent, "fazer_ping", return_value=(True, 2)):
            dados = self.agente.coletar()
            self.assertEqual(self.agente.enviar(dados), (True, 0))
        req = preparados[0]
        self.assertEqual(req.headers["Authorization"], "Bearer test-token")
        payload = json.loads(req.body)
        self.assertEqual(set(payload), {"hostname", "user_logon", "ip_local", "system_operacional",
                                        "machine_uuid", "status_lan", "time_ms_lan", "status_wan", "time_ms_wan", "medido_em", "boot_id", "sequencia"})
        self.assertIs(type(payload["status_lan"]), bool)
        self.assertIs(type(payload["time_ms_lan"]), int)

    def test_status_sem_redirecionamento(self):
        for codigo, sucesso in ((200, True), (204, True), (302, False), (401, False),
                                (403, False), (429, False), (500, False)):
            with self.subTest(codigo=codigo), patch.object(
                    self.agente.session, "post", return_value=self.resposta(codigo)) as post:
                self.assertEqual(self.agente.enviar({})[0], sucesso)
                self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_retry_after(self):
        with patch.object(self.agente.session, "post", return_value=self.resposta(429, {"Retry-After": "120"})):
            self.assertEqual(self.agente.enviar({}), (False, 120))
        self.assertEqual(agent.retry_after("invalid"), 0)
        self.assertEqual(agent.retry_after("99999999"), 86400)
        self.assertEqual(agent.retry_after("-10"), 0)
        self.assertGreater(agent.retry_after("Thu, 01 Jan 2099 00:00:00 GMT"), 0)

    def test_ca_explicita_e_passada_ao_requests(self):
        self.agente.config = {**CONFIG, "certificado_ca": "/teste/ca.crt"}
        with patch.object(self.agente.session, "post", return_value=self.resposta(200)) as post:
            self.agente.enviar({})
        self.assertEqual(post.call_args.kwargs["verify"], "/teste/ca.crt")

    def test_ssl_tem_diagnostico_sem_desabilitar_validacao(self):
        with patch.object(self.agente.session, "post", side_effect=requests.exceptions.SSLError), \
                self.assertLogs(agent.LOG, level="ERROR") as logs:
            self.assertEqual(self.agente.enviar({}), (False, 0))
        self.assertIn("certificado_ca", " ".join(logs.output))
        self.assertTrue(self.agente.session.verify)

    def test_timeout_comunicacao(self):
        with patch.object(self.agente.session, "post", side_effect=requests.Timeout):
            self.assertEqual(self.agente.enviar({}), (False, 0))

    def test_backoff_recupera_e_reinicia(self):
        with patch.object(self.agente, "coletar", return_value={}), \
                patch.object(self.agente, "enviar", side_effect=[(False, 0), (False, 0), (True, 0)]), \
                patch.object(agent.random, "uniform", return_value=0):
            self.assertEqual([self.agente.ciclo() for _ in range(3)], [20, 40, 20])
            self.assertEqual(self.agente.falhas, 0)

    def test_erro_de_identidade_nao_envia(self):
        with patch.object(self.agente, "coletar", side_effect=ValueError), \
                patch.object(self.agente, "enviar") as enviar:
            self.assertGreaterEqual(self.agente.ciclo(), 20)
            enviar.assert_not_called()

    def test_coletor_com_falha_preserva_outros_campos(self):
        self.agente.identidade = IDENTIDADE
        with patch.object(agent, "get_system_operacional", return_value="Linux"), \
                patch.object(agent, "get_rede", side_effect=OSError), \
                patch.object(agent, "get_user_logon", side_effect=OSError), \
                patch.object(agent, "fazer_ping", return_value=(False, None)):
            dados = self.agente.coletar()
        self.assertEqual(dados["machine_uuid"], IDENTIDADE)
        self.assertEqual(dados["ip_local"], "Desconhecido")
        self.assertIsNone(dados["time_ms_lan"])


    def test_aceito_false_nao_e_sucesso(self):
        resposta = self.resposta(200)
        resposta._content = b'{"status":"ok","aceito":false,"host_id":1}'
        with patch.object(self.agente.session, "post", return_value=resposta):
            self.assertEqual(self.agente.enviar({}), (False, 0))

    def test_diagnostico_vinculacao_sem_expor_corpo(self):
        resposta = self.resposta(403)
        resposta._content = json.dumps({"erro": "Host legado exige vinculação administrativa.",
                                        "token": "segredo-nao-logar"}).encode()
        with patch.object(self.agente.session, "post", return_value=resposta), \
                self.assertLogs(agent.LOG, level="ERROR") as logs:
            self.agente.enviar({})
        self.assertIn("bind-agent", " ".join(logs.output))
        self.assertNotIn("segredo-nao-logar", " ".join(logs.output))

    def test_sequencia_crescente_e_boot_por_execucao(self):
        self.agente.identidade = IDENTIDADE
        with patch.object(agent, "get_system_operacional", return_value="Windows"), \
                patch.object(agent, "get_rede", return_value=("10.0.0.2", "10.0.0.1")), \
                patch.object(agent, "get_user_logon", return_value="usuario"), \
                patch.object(agent, "fazer_ping", return_value=(True, 1)):
            primeiro, segundo = self.agente.coletar(), self.agente.coletar()
        self.assertEqual((primeiro["sequencia"], segundo["sequencia"]), (1, 2))
        self.assertEqual(primeiro["boot_id"], segundo["boot_id"])
        self.assertIsNotNone(agent.datetime.fromisoformat(primeiro["medido_em"]).tzinfo)
        outro = agent.Agente(CONFIG)
        self.addCleanup(outro.close)
        self.assertNotEqual(self.agente.boot_id, outro.boot_id)


if __name__ == "__main__":
    unittest.main()
