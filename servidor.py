#!/usr/bin/env python3
import asyncio
from tcp import Servidor
import re

nick_map = {}
channels = {}

def validar_nome(nome):
    return re.match(br'^[a-zA-Z][a-zA-Z0-9_-]*$', nome) is not None

def enviar(conexao, msg):
    conexao.enviar((msg + "\r\n").encode("utf-8"))

def sair(conexao):
    nick = getattr(conexao, 'nick', None)
    if nick:
        # Notificar canais que o usuário saiu
        for cset in channels.values():
            if conexao in cset:
                for outro in cset:
                    if outro != conexao:
                        enviar(outro, f":{nick} QUIT :Connection closed")
                cset.remove(conexao)
        # Remover dos mapas
        lower_nick = getattr(conexao, 'lower_nick', None)
        if lower_nick in nick_map:
            del nick_map[lower_nick]
    print(conexao, 'conexão fechada')
    conexao.fechar()

def compartilham_canal(connA, connB):
    """Retorna True se connA e connB participam de pelo menos um canal em comum."""
    for cset in channels.values():
        if connA in cset and connB in cset:
            return True
    return False

def process_line(conexao, line):
    nick = getattr(conexao, 'nick', None)
    lower_nick = getattr(conexao, 'lower_nick', None)
    parts = line.split(b' ', 1)
    if not parts:
        return
    cmd = parts[0].upper()

    if cmd == b'PING':  # Passo 1
        payload = b''
        if len(parts) > 1:
            payload = parts[1]
        enviar(conexao, f":server PONG server :{payload.decode('utf-8', 'ignore')}")

    elif cmd == b'NICK':  # Passos 3 e 4
        new_nick = b''
        if len(parts) > 1:
            new_nick = parts[1].strip()
        old_nick = nick if nick else '*'
        # Validar
        if not validar_nome(new_nick):
            enviar(conexao, f":server 432 {old_nick} {new_nick.decode()} :Erroneous nickname")
            return
        # Verificar duplicado
        lower_new = new_nick.decode().lower()
        if lower_new in nick_map and nick_map[lower_new] != conexao:
            enviar(conexao, f":server 433 {old_nick} {new_nick.decode()} :Nickname is already in use")
            return
        # Se for mudança e já tinha apelido
        if nick:
            # Remover do mapa antigo
            if lower_nick in nick_map:
                del nick_map[lower_nick]
            # Só notifica quem compartilha algum canal.
            # 1) Notifica quem compartilha canal
            for other_con in nick_map.values():
                if other_con != conexao and compartilham_canal(other_con, conexao):
                    enviar(other_con, f":{old_nick} NICK {new_nick.decode()}")
            # 2) Notifica o próprio usuário que mudou o nick (sempre)
            enviar(conexao, f":{old_nick} NICK {new_nick.decode()}")
        else:
            # Mensagens de registro ao definir apelido pela primeira vez
            enviar(conexao, f":server 001 {new_nick.decode()} :Welcome")
            enviar(conexao, f":server 422 {new_nick.decode()} :MOTD File is missing")

        conexao.nick = new_nick.decode()
        conexao.lower_nick = lower_new
        nick_map[lower_new] = conexao

    elif cmd == b'PRIVMSG':  # Passo 5 e 6
        if len(parts) < 2:
            return
        msg_part = parts[1].split(b' ', 1)
        if len(msg_part) < 2:
            return
        destinatario = msg_part[0].decode()
        conteudo = msg_part[1].lstrip(b':').decode('utf-8', 'ignore')
        # Canal ou user?
        if destinatario.startswith('#'):
            canal_lower = destinatario.lower()
            if canal_lower in channels:
                for outro in channels[canal_lower]:
                    if outro != conexao:
                        enviar(outro, f":{nick} PRIVMSG {destinatario} :{conteudo}")
        else:
            # user
            d_lower = destinatario.lower()
            if d_lower in nick_map:
                enviar(nick_map[d_lower], f":{nick} PRIVMSG {destinatario} :{conteudo}")

    elif cmd == b'JOIN':  # Passo 6 e 9
        if len(parts) < 2:
            return
        canal = parts[1].strip().decode()
        canal_lower = canal.lower()
        if not canal.startswith('#') or not validar_nome(canal_lower.encode()[1:]):
            enviar(conexao, f":server 403 {canal} :No such channel")
            return
        channels.setdefault(canal_lower, set())
        cset = channels[canal_lower]
        for outro in cset:
            enviar(outro, f":{nick} JOIN :{canal}")
        cset.add(conexao)
        enviar(conexao, f":{nick} JOIN :{canal}")
        # 353 e 366
        membros = sorted([getattr(u, 'nick', '') for u in cset], key=str.lower)
        membros_str = " ".join(membros)
        base_msg = f":server 353 {nick} = {canal} :"
        while len(base_msg + membros_str) >= 510:
            # break it
            cut_point = 510 - len(base_msg)
            piece = membros_str[:cut_point]
            membros_str = membros_str[cut_point:].lstrip()
            enviar(conexao, base_msg + piece)
        enviar(conexao, base_msg + membros_str)
        enviar(conexao, f":server 366 {nick} {canal} :End of /NAMES list.")

    elif cmd == b'PART':  # Passo 7
        if len(parts) < 2:
            return
        subparts = parts[1].split(b' ', 1)
        canal = subparts[0].decode()
        canal_lower = canal.lower()
        if canal_lower not in channels:
            return
        cset = channels[canal_lower]
        if conexao in cset:
            for outro in cset:
                enviar(outro, f":{nick} PART {canal}")
            cset.remove(conexao)

def dados_recebidos(conexao, dados):
    if not hasattr(conexao, 'buffer'):
        conexao.buffer = b''
    if dados == b'':
        return sair(conexao)
    conexao.buffer += dados
    while b'\r\n' in conexao.buffer:
        line, conexao.buffer = conexao.buffer.split(b'\r\n', 1)
        line = line.strip(b'\n\r')
        if line:
            process_line(conexao, line)

def conexao_aceita(conexao):
    print(conexao, 'nova conexão')

    def wrapper(c, d):
        try:
            dados_recebidos(c, d)
        except ConnectionResetError:
            sair(c)

    conexao.registrar_recebedor(wrapper)

if __name__ == "__main__":
    servidor = Servidor(6667)
    servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)
    asyncio.get_event_loop().run_forever()
