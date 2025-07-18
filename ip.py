from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            if ttl <= 1:
                # TTL expirou, gera ICMP Time Exceeded para o remetente
                # ICMP header: Type (8b), Code (8b), Checksum (16b), Unused (32b)
                icmp_type = 11  # Time Exceeded
                icmp_code = 0
                icmp_unused = 0
                # O payload do ICMP deve conter o cabeçalho IP original + 8 bytes do payload original
                original_header = datagrama[:20]
                original_payload = datagrama[20:28] if len(datagrama) > 28 else datagrama[20:]
                icmp_payload = original_header + original_payload
                icmp_header = struct.pack('!BBHI', icmp_type, icmp_code, 0, icmp_unused)
                icmp_datagram = icmp_header + icmp_payload
                # Calcula checksum ICMP
                icmp_checksum = calc_checksum(icmp_datagram)
                icmp_header = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, icmp_unused)
                icmp_datagram = icmp_header + icmp_payload
                # Monta datagrama IP para ICMP
                version = 4
                ihl = 5
                vihl = (version << 4) + ihl
                dscpecn = (dscp << 2) + ecn
                total_len = 20 + len(icmp_datagram)
                flagsfrag = (flags << 13) + frag_offset
                novo_ttl = 64
                proto_num = IPPROTO_ICMP
                checksum = 0
                src_addr_bytes = str2addr(self.meu_endereco)
                dst_addr_bytes = str2addr(src_addr)
                cabecalho = struct.pack('!BBHHHBBH4s4s',
                    vihl, dscpecn, total_len, identification, flagsfrag, novo_ttl, proto_num, checksum, src_addr_bytes, dst_addr_bytes)
                checksum = calc_checksum(cabecalho)
                cabecalho = struct.pack('!BBHHHBBH4s4s',
                    vihl, dscpecn, total_len, identification, flagsfrag, novo_ttl, proto_num, checksum, src_addr_bytes, dst_addr_bytes)
                datagrama_icmp = cabecalho + icmp_datagram
                next_hop_icmp = self._next_hop(src_addr)
                self.enlace.enviar(datagrama_icmp, next_hop_icmp)
                return
            novo_ttl = ttl - 1
            # Reconstrói o cabeçalho IP com novo TTL e checksum
            version = 4
            ihl = 5
            vihl = (version << 4) + ihl
            dscpecn = (dscp << 2) + ecn
            total_len = 20 + len(payload)
            flagsfrag = (flags << 13) + frag_offset
            proto_num = proto
            checksum = 0
            src_addr_bytes = str2addr(src_addr)
            dst_addr_bytes = str2addr(dst_addr)
            cabecalho = struct.pack('!BBHHHBBH4s4s',
                vihl, dscpecn, total_len, identification, flagsfrag, novo_ttl, proto_num, checksum, src_addr_bytes, dst_addr_bytes)
            checksum = calc_checksum(cabecalho)
            cabecalho = struct.pack('!BBHHHBBH4s4s',
                vihl, dscpecn, total_len, identification, flagsfrag, novo_ttl, proto_num, checksum, src_addr_bytes, dst_addr_bytes)
            novo_datagrama = cabecalho + payload
            self.enlace.enviar(novo_datagrama, next_hop)

    def _next_hop(self, dest_addr):
        dest_int = int.from_bytes(str2addr(dest_addr), 'big')
        melhor_prefixo = -1
        melhor_next_hop = None
        for rede_int, mascara, next_hop in self.tabela_encaminhamento:
            if (dest_int & mascara) == (rede_int & mascara):
                prefixo = bin(mascara).count('1')
                if prefixo > melhor_prefixo:
                    melhor_prefixo = prefixo
                    melhor_next_hop = next_hop
        return melhor_next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_encaminhamento = []
        for cidr, next_hop in tabela:
            rede, prefixo = cidr.split('/')
            rede_int = int.from_bytes(str2addr(rede), 'big')
            prefixo = int(prefixo)
            mascara = (0xFFFFFFFF << (32 - prefixo)) & 0xFFFFFFFF
            self.tabela_encaminhamento.append((rede_int, mascara, next_hop))

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # Cabeçalho IPv4
        version = 4
        ihl = 5  # sem opções
        vihl = (version << 4) + ihl
        dscp = 0
        ecn = 0
        dscpecn = (dscp << 2) + ecn
        total_len = 20 + len(segmento)
        identification = 0
        flags = 0
        frag_offset = 0
        flagsfrag = (flags << 13) + frag_offset
        ttl = 64
        proto = IPPROTO_TCP
        checksum = 0
        src_addr = str2addr(self.meu_endereco)
        dst_addr = str2addr(dest_addr)
        # Monta cabeçalho sem checksum
        cabecalho = struct.pack('!BBHHHBBH4s4s',
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dst_addr)
        # Calcula checksum
        checksum = calc_checksum(cabecalho)
        # Monta cabeçalho final com checksum
        cabecalho = struct.pack('!BBHHHBBH4s4s',
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dst_addr)
        datagrama = cabecalho + segmento
        self.enlace.enviar(datagrama, next_hop)
