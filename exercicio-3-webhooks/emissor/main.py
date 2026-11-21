import asyncio
import hashlib
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Dict, Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

# Carrega variáveis de ambiente de um arquivo .env se existir
load_dotenv()

# Configuração de logs
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [EMISSOR] %(levelname)s: %(message)s"
)
logger = logging.getLogger("emissor")

# Variáveis de ambiente configuráveis
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://localhost:8001/webhook")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "meu_segredo_super_secreto_123")
INTERVALO_SEGUNDOS = int(os.getenv("INTERVALO_SEGUNDOS", "5"))

# Fluxo de transição de status dos pedidos
PROXIMO_STATUS = {
    "recebido": "aprovado",
    "aprovado": "enviado",
    "enviado": "entregue",
}

# Armazenamento em memória dos pedidos
# Estrutura: { pedido_id: {"pedido_id": str, "status": str} }
pedidos_db: Dict[str, Dict[str, Any]] = {}

# Contador sequencial para geração de IDs únicos de eventos
contador_eventos = 0
contador_lock = asyncio.Lock()


def gerar_assinatura_hmac(corpo_bytes: bytes, segredo: str) -> str:
    """Calcula a assinatura HMAC-SHA256 no formato sha256=<64_hex>."""
    mac = hmac.new(segredo.encode("utf-8"), corpo_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


async def notificar_webhook_com_reentrega(evento: Dict[str, Any]) -> None:
    """
    Envia o evento via POST para o webhook com cabeçalho X-Assinatura.
    Serializa o corpo uma única vez em bytes para garantir integridade.
    Caso não receba resposta 2xx, tenta reenviar até 3 vezes mantendo o mesmo id de evento.
    """
    corpo_bytes = json.dumps(evento, separators=(",", ":")).encode("utf-8")
    assinatura = gerar_assinatura_hmac(corpo_bytes, WEBHOOK_SECRET)

    headers = {
        "Content-Type": "application/json",
        "X-Assinatura": assinatura,
    }

    max_tentativas = 3
    for tentativa in range(1, max_tentativas + 1):
        try:
            logger.info(
                f"Tentativa {tentativa}/{max_tentativas} de envio do evento {evento['id']} "
                f"para {WEBHOOK_URL} (Pedido: {evento['pedido_id']}, Novo Status: {evento['status']})"
            )
            async with httpx.AsyncClient(timeout=5.0) as client:
                resposta = await client.post(
                    WEBHOOK_URL,
                    content=corpo_bytes,
                    headers=headers
                )

                if resposta.is_success:
                    logger.info(
                        f"Evento {evento['id']} entregue com sucesso! Status HTTP: {resposta.status_code}"
                    )
                    return
                else:
                    logger.warning(
                        f"Receptor respondeu com erro {resposta.status_code} para o evento {evento['id']}."
                    )
        except Exception as e:
            logger.warning(
                f"Falha de conexão na tentativa {tentativa}/{max_tentativas} para evento {evento['id']}: {e}"
            )

        if tentativa < max_tentativas:
            # Espera 1 segundo antes de tentar novamente a reentrega
            await asyncio.sleep(1)

    logger.error(f"Esgotadas as tentativas de reentrega para o evento {evento['id']}.")


async def processador_pedidos_background() -> None:
    """
    Tarefa em segundo plano que avança os pedidos na sequência:
    recebido -> aprovado -> enviado -> entregue.
    Pedidos 'entregue' não avançam mais.
    """
    global contador_eventos
    logger.info(
        f"Iniciando tarefa em segundo plano de processamento de pedidos (intervalo: {INTERVALO_SEGUNDOS}s)..."
    )

    while True:
        try:
            await asyncio.sleep(INTERVALO_SEGUNDOS)

            # Itera sobre os pedidos para verificar se podem avançar de status
            for pedido_id, pedido in list(pedidos_db.items()):
                status_atual = pedido["status"]

                if status_atual in PROXIMO_STATUS:
                    novo_status = PROXIMO_STATUS[status_atual]
                    pedido["status"] = novo_status

                    # Gera um novo identificador único de evento
                    async with contador_lock:
                        contador_eventos += 1
                        evento_id = f"evt_{contador_eventos}"

                    payload_evento = {
                        "id": evento_id,
                        "pedido_id": pedido_id,
                        "status": novo_status,
                    }

                    logger.info(
                        f"Pedido '{pedido_id}' avançou: '{status_atual}' -> '{novo_status}'. "
                        f"Disparando webhook com evento '{evento_id}'."
                    )

                    # Dispara o envio do webhook de forma assíncrona
                    asyncio.create_task(notificar_webhook_com_reentrega(payload_evento))

        except asyncio.CancelledError:
            logger.info("Tarefa de processamento em segundo plano finalizada.")
            break
        except Exception as e:
            logger.error(f"Erro inesperado no loop em segundo plano: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializa a tarefa de fundo ao iniciar a aplicação
    task = asyncio.create_task(processador_pedidos_background())
    yield
    # Cancela a tarefa ao desligar a aplicação
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Emissor de Webhooks - Pedidos", lifespan=lifespan)


class RespostaPedido(BaseModel):
    pedido_id: str
    status: str


@app.post(
    "/pedidos/{pedido_id}",
    status_code=status.HTTP_201_CREATED,
    response_model=RespostaPedido,
    summary="Cadastrar um novo pedido"
)
async def cadastrar_pedido(pedido_id: str):
    """
    Cadastra um novo pedido com status inicial 'recebido'.
    Caso o pedido já exista, responde com status 409 (Conflict).
    """
    if pedido_id in pedidos_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Pedido com id '{pedido_id}' já existe."
        )

    novo_pedido = {
        "pedido_id": pedido_id,
        "status": "recebido",
    }
    pedidos_db[pedido_id] = novo_pedido
    logger.info(f"Pedido '{pedido_id}' cadastrado com sucesso com status 'recebido'.")

    return novo_pedido


@app.get("/pedidos", summary="Listar pedidos cadastrados no emissor")
async def listar_pedidos():
    """Retorna a lista de todos os pedidos e seus status atuais."""
    return list(pedidos_db.values())
