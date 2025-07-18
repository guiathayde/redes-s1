class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self._recv_buffer = bytearray()
        self._frame_buffer = bytearray()
        self.callback = None

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        SLIP_END = 0xC0
        SLIP_ESC = 0xDB
        SLIP_ESC_END = 0xDC
        SLIP_ESC_ESC = 0xDD
        # Aplica escape nos bytes do datagrama
        quadro = bytearray()
        quadro.append(SLIP_END)
        for byte in datagrama:
            if byte == SLIP_END:
                quadro.append(SLIP_ESC)
                quadro.append(SLIP_ESC_END)
            elif byte == SLIP_ESC:
                quadro.append(SLIP_ESC)
                quadro.append(SLIP_ESC_ESC)
            else:
                quadro.append(byte)
        quadro.append(SLIP_END)
        self.linha_serial.enviar(bytes(quadro))

    def __raw_recv(self, dados):
        SLIP_END = 0xC0
        SLIP_ESC = 0xDB
        SLIP_ESC_END = 0xDC
        SLIP_ESC_ESC = 0xDD
        for byte in dados:
            if byte == SLIP_END:
                if len(self._frame_buffer) > 0:
                    # Desescape
                    datagrama = bytearray()
                    i = 0
                    while i < len(self._frame_buffer):
                        if self._frame_buffer[i] == SLIP_ESC:
                            if i+1 < len(self._frame_buffer):
                                if self._frame_buffer[i+1] == SLIP_ESC_END:
                                    datagrama.append(SLIP_END)
                                    i += 2
                                elif self._frame_buffer[i+1] == SLIP_ESC_ESC:
                                    datagrama.append(SLIP_ESC)
                                    i += 2
                                else:
                                    datagrama.append(SLIP_ESC)
                                    i += 1
                            else:
                                datagrama.append(SLIP_ESC)
                                i += 1
                        else:
                            datagrama.append(self._frame_buffer[i])
                            i += 1
                    if len(datagrama) > 0 and self.callback:
                        try:
                            self.callback(bytes(datagrama))
                        except Exception:
                            import traceback
                            traceback.print_exc()
                        finally:
                            # Limpa o buffer do quadro, mesmo em caso de erro
                            self._frame_buffer = bytearray()
                    else:
                        self._frame_buffer = bytearray()
                else:
                    self._frame_buffer = bytearray()
            else:
                self._frame_buffer.append(byte)
