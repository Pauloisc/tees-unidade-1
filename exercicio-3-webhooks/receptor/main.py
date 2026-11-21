import hashlib
import hmac
import json
import logging
import os
from typing import Dict, Any, List, Set

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

# Carrega variáveis de ambiente de um arquivo .env se existir
load_dotenv()

# Configuração de logs
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [RECEPTOR] %(levelname)s: %(message)s"
)
logger = logging.getLogger("receptor")

# Segredo compartilhado obtido via variável de ambiente
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "meu_segredo_super_secreto_123")

# Armazenamento em memória dos eventos recebidos
eventos_db: List[Dict[str, Any]] = []

# Conjunto de IDs de eventos já processados para garantir idempotência
ids_eventos_processados: Set[str] = set()

app = FastAPI(title="Receptor de Webhooks - Eventos")


def validar_assinatura(corpo_bytes: bytes, cabecalho_assinatura: str | None, segredo: str) -> bool:
    """
    Valida a assinatura HMAC-SHA256 recebida no cabeçalho X-Assinatura.
    Espera o formato 'sha256=<64_hex>'.
    Usa hmac.compare_digest para prevenção de ataques de temporização (timing attacks).
    """
    if not cabecalho_assinatura:
        logger.warning("Cabeçalho X-Assinatura ausente na requisição.")
        return False

    prefixo = "sha256="
    if not cabecalho_assinatura.startswith(prefixo):
        logger.warning(f"Formato inválido de X-Assinatura: '{cabecalho_assinatura}'.")
        return False

    assinatura_fornecida = cabecalho_assinatura[len(prefixo):]

    # Recalcula o HMAC sobre os bytes exatos recebidos
    mac = hmac.new(segredo.encode("utf-8"), corpo_bytes, hashlib.sha256)
    assinatura_esperada = mac.hexdigest()

    valido = hmac.compare_digest(assinatura_fornecida, assinatura_esperada)
    if not valido:
        logger.warning(
            f"Assinatura inválida! Esperada: {assinatura_esperada[:10]}..., Recebida: {assinatura_fornecida[:10]}..."
        )
    return valido


@app.post(
    "/webhook",
    summary="Receber evento via Webhook",
    status_code=status.HTTP_200_OK
)
async def receber_webhook(request: Request):
    """
    Recebe eventos de webhook enviados pelo emissor.
    1. Lê os bytes brutos antes de converter em JSON.
    2. Valida o cabeçalho X-Assinatura com HMAC-SHA256 e compare_digest.
    3. Se inválida ou ausente, responde 401 Unauthorized e não registra o evento.
    4. Verifica idempotência pelo 'id' do evento: se já processado, retorna 200 OK sem duplicar.
    5. Registra o evento na lista de eventos.
    """
    corpo_bytes = await request.body()
    cabecalho_assinatura = request.headers.get("X-Assinatura")

    # Extra 1: Validação de segurança HMAC-SHA256
    if not validar_assinatura(corpo_bytes, cabecalho_assinatura, WEBHOOK_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura ausente ou inválida."
        )

    # Conversão para JSON após validação da integridade e autenticidade
    try:
        dados_evento = json.loads(corpo_bytes.decode("utf-8"))
    except Exception as e:
        logger.error(f"Erro ao converter corpo recebido para JSON: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Corpo JSON inválido."
        )

    evento_id = dados_evento.get("id")
    if not evento_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O campo 'id' do evento é obrigatório."
        )

    # Extra 2: Verificação de Idempotência
    if evento_id in ids_eventos_processados:
        logger.info(
            f"Evento duplicado ignorado (idempotência): '{evento_id}' já havia sido processado anteriormente."
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "mensagem": "Evento já processado anteriormente (idempotência).",
                "id": evento_id,
                "duplicado": True
            }
        )

    # Registro do evento único
    ids_eventos_processados.add(evento_id)
    eventos_db.append(dados_evento)

    logger.info(
        f"Evento '{evento_id}' registrado com sucesso! "
        f"(Pedido: {dados_evento.get('pedido_id')}, Status: {dados_evento.get('status')})"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "mensagem": "Evento recebido e registrado com sucesso.",
            "id": evento_id,
            "duplicado": False
        }
    )


@app.get(
    "/eventos",
    summary="Listar todos os eventos registrados",
    status_code=status.HTTP_200_OK
)
async def listar_eventos():
    """Retorna todos os eventos recebidos e registrados até o momento."""
    return eventos_db
