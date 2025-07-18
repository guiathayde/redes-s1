import asyncio
from tcputils import *
import random
import time

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            if id_conexao in self.conexoes and self.conexoes[id_conexao].closed:
                del self.conexoes[id_conexao]

            if id_conexao not in self.conexoes:
                conexao = self.conexoes[id_conexao] = Conexao(
                    self, id_conexao, seq_no + 1
                )
                conexao.srv_seq = random.randint(0, 0xffffffff)
                conexao.ack_no_expected_from_client = seq_no + 1 

                synack_flags = FLAGS_SYN | FLAGS_ACK
                synack_seg = make_header(
                    self.porta, src_port, conexao.srv_seq, conexao.ack_no_expected_from_client, synack_flags
                )
                synack_seg = fix_checksum(synack_seg, dst_addr, src_addr)
                self.rede.enviar(synack_seg, src_addr)
                
                conexao.srv_seq += 1 
                conexao.env_base = conexao.srv_seq 
                
                if self.callback:
                    self.callback(conexao)
            return

        if id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            pass


class Conexao:
    def __init__(self, servidor, id_conexao, expected_seq_no_from_client):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        
        self.srv_seq = 0 
        self.ack_no_expected_from_client = 0 
        self.next_seq_no_to_receive = expected_seq_no_from_client
        
        self.cli_addr, self.cli_port, self.srv_addr, self.srv_port = id_conexao
        
        self.send_buffer = b''
        self.unacked_segments = []
        
        self.env_base = 0 
        self.timer = None
        self.TimeoutInterval = 1.0 
        
        self.EstimatedRTT = None
        self.DevRTT = None
        self.first_rtt_measurement = True

        self.cwnd = float(MSS) 
        self.ssthresh = float(65535) 
        self.bytes_in_flight = 0.0
        self.acked_bytes_towards_cwnd_increase = 0.0 
        self.duplicate_ack_count = 0

        self.closed = False
        self.fin_sent = False
        self.fin_received = False

    def _start_timer(self):
        self._stop_timer()
        if not self.unacked_segments or self.closed:
            return
        loop = asyncio.get_event_loop()
        self.timer = loop.call_later(self.TimeoutInterval, self._timeout)

    def _stop_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _update_rtt(self, sample_rtt):
        if self.first_rtt_measurement:
            self.EstimatedRTT = sample_rtt
            self.DevRTT = sample_rtt / 2.0
            self.first_rtt_measurement = False
        else:
            alpha = 0.125
            beta = 0.25
            self.DevRTT = (1 - beta) * self.DevRTT + beta * abs(sample_rtt - self.EstimatedRTT)
            self.EstimatedRTT = (1 - alpha) * self.EstimatedRTT + alpha * sample_rtt
        
        self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT
        self.TimeoutInterval = max(self.TimeoutInterval, 0.2)

    def _timeout(self):
        if not self.unacked_segments or self.closed:
            self.timer = None 
            return
        
        ssthresh_candidate = self.bytes_in_flight if self.bytes_in_flight > 0 else self.cwnd
        self.ssthresh = max(ssthresh_candidate / 2.0, float(MSS)) 
                                                                    
        self.cwnd = float(MSS) 
        self.duplicate_ack_count = 0
        self.acked_bytes_towards_cwnd_increase = 0.0

        seq, segment_to_retransmit, _, _ = self.unacked_segments[0]
        self.unacked_segments[0] = (seq, segment_to_retransmit, time.time(), True)
        self.servidor.rede.enviar(segment_to_retransmit, self.cli_addr)
        self._start_timer()

    def _rdt_rcv(self, seq_no_cli, ack_no_cli, flags, payload):
        if self.closed:
            return

        process_payload_for_app = (len(payload) > 0) and (not self.fin_received)

        is_control_or_data = len(payload) > 0 or (flags & FLAGS_FIN)
        if is_control_or_data:
            if seq_no_cli < self.next_seq_no_to_receive:
                self._send_ack()
                if not (flags & FLAGS_ACK): return
            elif seq_no_cli > self.next_seq_no_to_receive:
                self._send_ack()
                if not (flags & FLAGS_ACK): return
        
        if (flags & FLAGS_ACK):
            if self.fin_sent and ack_no_cli == self.srv_seq:
                if self.fin_received:
                    self._handle_connection_termination()
            
            elif ack_no_cli > self.env_base: 
                bytes_realmente_novos_reconhecidos = float(ack_no_cli - self.env_base)
                
                self.bytes_in_flight -= bytes_realmente_novos_reconhecidos
                self.bytes_in_flight = max(0.0, self.bytes_in_flight)

                acked_original_send_time = None
                is_retransmitted_acked = True 
                new_unacked_list = []
                processed_ack_for_rtt = False
                for seq, seg, t_envio, retransmitted_flag in self.unacked_segments:
                    seg_hdr_len = 4*(read_header(seg)[4]>>12)
                    seg_payload_len = len(seg[seg_hdr_len:])
                    seg_consumes_seq = seg_payload_len
                    if (read_header(seg)[4] & FLAGS_FIN or read_header(seg)[4] & FLAGS_SYN):
                        seg_consumes_seq +=1
                    
                    if seq + seg_consumes_seq <= ack_no_cli:
                        if not retransmitted_flag and not processed_ack_for_rtt:
                            acked_original_send_time = t_envio
                            is_retransmitted_acked = False
                            processed_ack_for_rtt = True 
                    else:
                        new_unacked_list.append((seq, seg, t_envio, retransmitted_flag))
                self.unacked_segments = new_unacked_list
                
                if acked_original_send_time and not is_retransmitted_acked:
                    sample_rtt = time.time() - acked_original_send_time
                    self._update_rtt(sample_rtt)

                self.env_base = ack_no_cli
                self.duplicate_ack_count = 0 

                self.acked_bytes_towards_cwnd_increase += bytes_realmente_novos_reconhecidos
                
                while self.acked_bytes_towards_cwnd_increase >= self.cwnd:
                    cwnd_valor_usado_para_credito = self.cwnd
                    self.cwnd += float(MSS)
                    self.acked_bytes_towards_cwnd_increase -= cwnd_valor_usado_para_credito
                    if self.acked_bytes_towards_cwnd_increase < 0:
                        self.acked_bytes_towards_cwnd_increase = 0.0
                    
                    if self.cwnd > self.ssthresh and cwnd_valor_usado_para_credito < self.ssthresh:
                        self.acked_bytes_towards_cwnd_increase = 0.0 
                        break
                
                if not self.unacked_segments:
                    self._stop_timer()
                else:
                    self._start_timer()
                
                self._try_send_buffered_data()

            elif ack_no_cli == self.env_base and len(payload) == 0 and not (flags & FLAGS_SYN or flags & FLAGS_FIN):
                if not (self.fin_sent and ack_no_cli == self.srv_seq):
                    self.duplicate_ack_count += 1
                    if self.duplicate_ack_count == 3:
                        ssthresh_candidate_fr = self.bytes_in_flight if self.bytes_in_flight > 0 else self.cwnd
                        self.ssthresh = max(ssthresh_candidate_fr / 2.0, float(MSS))
                        
                        self.cwnd = self.ssthresh + 3.0 * MSS
                        self.acked_bytes_towards_cwnd_increase = 0.0
                        
                        if self.unacked_segments:
                            seq_to_retransmit, seg_to_retransmit, t_orig, _ = self.unacked_segments[0]
                            self.unacked_segments[0] = (seq_to_retransmit, seg_to_retransmit, time.time(), True)
                            self.servidor.rede.enviar(seg_to_retransmit, self.cli_addr)
                            self._start_timer()
        
        if process_payload_for_app:
            if seq_no_cli == self.next_seq_no_to_receive: 
                self.next_seq_no_to_receive += len(payload)
                if self.callback:
                    self.callback(self, payload)
                self._send_ack() 
        elif len(payload) > 0 and self.fin_received :
             if seq_no_cli == self.next_seq_no_to_receive :
                  self.next_seq_no_to_receive += len(payload)
                  self._send_ack()
             elif seq_no_cli < self.next_seq_no_to_receive :
                  self._send_ack()

        if (flags & FLAGS_FIN):
            if seq_no_cli == self.next_seq_no_to_receive: 
                self.next_seq_no_to_receive += 1
                self.fin_received = True
                if self.callback:
                    self.callback(self, b'')
                self._send_ack() 
                if self.fin_sent:
                    self._handle_connection_termination()
            elif seq_no_cli < self.next_seq_no_to_receive and self.fin_received :
                 self._send_ack()

    def _send_ack(self):
        if self.closed:
            return
        ack_segment = make_header(self.srv_port, self.cli_port, self.srv_seq, self.next_seq_no_to_receive, FLAGS_ACK)
        ack_segment = fix_checksum(ack_segment, self.srv_addr, self.cli_addr)
        self.servidor.rede.enviar(ack_segment, self.cli_addr)

    def _send_segment(self, payload=b'', flags=0):
        if self.closed:
            return

        seq_no_to_send = self.srv_seq
        ack_no_in_header = self.next_seq_no_to_receive
        current_flags = flags | FLAGS_ACK
        if (flags & FLAGS_SYN) and not (flags & FLAGS_ACK):
            current_flags = FLAGS_SYN
        
        header = make_header(self.srv_port, self.cli_port, seq_no_to_send, ack_no_in_header, current_flags)
        segment = fix_checksum(header + payload, self.srv_addr, self.cli_addr)
        
        consumes_seq_no = len(payload) > 0 or (current_flags & FLAGS_SYN) or (current_flags & FLAGS_FIN)

        if consumes_seq_no:
            self.unacked_segments.append((seq_no_to_send, segment, time.time(), False))
            self.bytes_in_flight += len(payload)

        self.servidor.rede.enviar(segment, self.cli_addr)

        if len(payload) > 0:
            self.srv_seq += len(payload)
        if (current_flags & FLAGS_SYN) or (current_flags & FLAGS_FIN):
            self.srv_seq += 1 

        if consumes_seq_no:
            self._start_timer()
        
    def _try_send_buffered_data(self):
        if self.closed: return

        while len(self.send_buffer) > 0:
            available_window_bytes = self.cwnd - self.bytes_in_flight
            if available_window_bytes < 1.0 :
                break 
            data_to_send_len = min(len(self.send_buffer), MSS) 
            data_to_send_len = min(data_to_send_len, int(available_window_bytes))
            if data_to_send_len <= 0 :
                 break
            payload_chunk = self.send_buffer[:data_to_send_len]
            self.send_buffer = self.send_buffer[data_to_send_len:]
            self._send_segment(payload=payload_chunk, flags=FLAGS_ACK)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados): 
        if self.closed or self.fin_sent:
            return
        self.send_buffer += dados
        self._try_send_buffered_data()

    def fechar(self): 
        if self.fin_sent or self.closed:
            return
        self._try_send_buffered_data() 
        self.fin_sent = True
        self._send_segment(flags=FLAGS_FIN)

    def _handle_connection_termination(self):
        if not self.closed:
            self.closed = True
            self._stop_timer()
            if self.id_conexao in self.servidor.conexoes and self.servidor.conexoes[self.id_conexao] is self:
                del self.servidor.conexoes[self.id_conexao]
