#!/usr/bin/env python3
"""
Высокопроизводительный захват пакетов в линию для DPI системы
Использует кольцевые буферы, многопоточность и оптимизированную обработку
"""

import threading
import queue
import time
import struct
import socket
import select
import mmap
import ctypes
from collections import deque, namedtuple
from dataclasses import dataclass
from typing import Callable, Optional, List, Dict, Any
from datetime import datetime
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor
import psutil
import logging

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Установите scapy: pip install scapy")
    raise

# Структуры данных для высокопроизводительной обработки
PacketMetadata = namedtuple('PacketMetadata', [
    'timestamp', 'size', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
    'protocol', 'flags', 'payload_offset', 'payload_size'
])

@dataclass
class CaptureStats:
    """Статистика захвата пакетов"""
    packets_captured: int = 0
    packets_processed: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    capture_rate: float = 0.0
    processing_rate: float = 0.0
    buffer_utilization: float = 0.0
    last_update: datetime = None

class RingBuffer:
    """Кольцевой буфер для высокопроизводительного захвата"""
    
    def __init__(self, size: int = 1024 * 1024):
        self.size = size
        self.buffer = bytearray(size)
        self.write_pos = 0
        self.read_pos = 0
        self.lock = threading.RLock()
        self.not_empty = threading.Condition(self.lock)
        self.not_full = threading.Condition(self.lock)
        self.packet_offsets = deque(maxlen=10000)  # Смещения пакетов
        
    def write_packet(self, packet_data: bytes) -> bool:
        """Запись пакета в буфер"""
        packet_size = len(packet_data)
        
        with self.not_full:
            # Проверка свободного места
            available_space = self._get_available_write_space()
            if packet_size + 4 > available_space:  # +4 для размера пакета
                return False  # Буфер полон
            
            # Запись размера пакета
            size_bytes = struct.pack('I', packet_size)
            self._write_bytes(size_bytes)
            
            # Запись данных пакета
            self._write_bytes(packet_data)
            
            # Сохранение смещения для быстрого доступа
            self.packet_offsets.append((self.read_pos, packet_size))
            
            self.not_empty.notify()
            return True
    
    def read_packet(self, timeout: float = 1.0) -> Optional[bytes]:
        """Чтение пакета из буфера"""
        with self.not_empty:
            if not self.packet_offsets:
                if not self.not_empty.wait(timeout):
                    return None
                if not self.packet_offsets:
                    return None
            
            # Получение смещения следующего пакета
            offset, packet_size = self.packet_offsets.popleft()
            
            # Чтение размера пакета
            size_bytes = self._read_bytes(4)
            if not size_bytes:
                return None
            
            actual_size = struct.unpack('I', size_bytes)[0]
            
            # Чтение данных пакета
            packet_data = self._read_bytes(actual_size)
            return packet_data
    
    def _write_bytes(self, data: bytes):
        """Запись байтов в кольцевой буфер"""
        for byte in data:
            self.buffer[self.write_pos] = byte
            self.write_pos = (self.write_pos + 1) % self.size
    
    def _read_bytes(self, count: int) -> bytes:
        """Чтение байтов из кольцевого буфера"""
        result = bytearray()
        for _ in range(count):
            if self.read_pos == self.write_pos:
                break
            result.append(self.buffer[self.read_pos])
            self.read_pos = (self.read_pos + 1) % self.size
        return bytes(result)
    
    def _get_available_write_space(self) -> int:
        """Получение доступного места для записи"""
        if self.write_pos >= self.read_pos:
            return self.size - (self.write_pos - self.read_pos) - 1
        else:
            return self.read_pos - self.write_pos - 1
    
    def get_utilization(self) -> float:
        """Получение процента заполнения буфера"""
        used_space = self.size - self._get_available_write_space()
        return (used_space / self.size) * 100.0

class PacketProcessor:
    """Процессор пакетов для извлечения метаданных"""
    
    def __init__(self):
        self.stats = CaptureStats()
        self.start_time = time.time()
        
    def process_packet(self, packet_data: bytes) -> Optional[PacketMetadata]:
        """Быстрая обработка пакета для извлечения метаданных"""
        try:
            # Парсинг Ethernet заголовка
            if len(packet_data) < 14:
                return None
            
            eth_header = struct.unpack('!6s6sH', packet_data[:14])
            eth_type = eth_header[2]
            
            # Проверка на IPv4
            if eth_type != 0x0800:
                return None
            
            # Парсинг IP заголовка
            if len(packet_data) < 34:
                return None
            
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[14:34])
            version_ihl = ip_header[0]
            ihl = (version_ihl & 0x0F) * 4
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Парсинг портов для TCP/UDP
            src_port = dst_port = 0
            flags = 0
            payload_offset = 14 + ihl
            
            if protocol == 6:  # TCP
                if len(packet_data) >= payload_offset + 20:
                    tcp_header = struct.unpack('!HHLLBBHHH', 
                                             packet_data[payload_offset:payload_offset+20])
                    src_port = tcp_header[0]
                    dst_port = tcp_header[1]
                    flags = tcp_header[5]
                    tcp_header_len = ((tcp_header[4] >> 4) & 0x0F) * 4
                    payload_offset += tcp_header_len
                    
            elif protocol == 17:  # UDP
                if len(packet_data) >= payload_offset + 8:
                    udp_header = struct.unpack('!HHHH', 
                                             packet_data[payload_offset:payload_offset+8])
                    src_port = udp_header[0]
                    dst_port = udp_header[1]
                    payload_offset += 8
            
            payload_size = len(packet_data) - payload_offset
            
            self.stats.packets_processed += 1
            
            return PacketMetadata(
                timestamp=time.time(),
                size=len(packet_data),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                flags=flags,
                payload_offset=payload_offset,
                payload_size=payload_size
            )
            
        except Exception as e:
            logging.error(f"Ошибка обработки пакета: {e}")
            return None

class HighPerformanceCapture:
    """Высокопроизводительная система захвата пакетов"""
    
    def __init__(self, interface: str = None, buffer_size: int = 16*1024*1024):
        self.interface = interface
        self.buffer_size = buffer_size
        self.ring_buffer = RingBuffer(buffer_size)
        self.packet_processor = PacketProcessor()
        
        # Потоки и процессы
        self.capture_thread = None
        self.processing_threads = []
        self.num_processing_threads = min(8, mp.cpu_count())
        
        # Очереди для обработки
        self.processing_queue = queue.Queue(maxsize=10000)
        self.result_queue = queue.Queue(maxsize=10000)
        
        # Флаги управления
        self.running = False
        self.stats = CaptureStats()
        
        # Колбэки для обработки
        self.packet_callbacks: List[Callable] = []
        self.anomaly_callbacks: List[Callable] = []
        
        # Настройка логирования
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
    def add_packet_callback(self, callback: Callable[[PacketMetadata, bytes], None]):
        """Добавление колбэка для обработки пакетов"""
        self.packet_callbacks.append(callback)
    
    def add_anomaly_callback(self, callback: Callable[[Dict], None]):
        """Добавление колбэка для обработки аномалий"""
        self.anomaly_callbacks.append(callback)
    
    def start_capture(self):
        """Запуск захвата пакетов"""
        if self.running:
            return
        
        self.running = True
        self.logger.info(f"Запуск захвата на интерфейсе: {self.interface}")
        
        # Запуск потока захвата
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            name="PacketCapture"
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Запуск потоков обработки
        for i in range(self.num_processing_threads):
            thread = threading.Thread(
                target=self._processing_worker,
                name=f"PacketProcessor-{i}"
            )
            thread.daemon = True
            thread.start()
            self.processing_threads.append(thread)
        
        # Запуск потока статистики
        stats_thread = threading.Thread(
            target=self._stats_worker,
            name="StatsCollector"
        )
        stats_thread.daemon = True
        stats_thread.start()
        
        self.logger.info(f"Захват запущен с {self.num_processing_threads} потоками обработки")
    
    def stop_capture(self):
        """Остановка захвата пакетов"""
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        for thread in self.processing_threads:
            thread.join(timeout=5)
        
        self.logger.info("Захват остановлен")
    
    def _capture_worker(self):
        """Рабочий поток захвата пакетов"""
        try:
            # Создание raw socket для захвата
            if self.interface:
                # Использование scapy для захвата на конкретном интерфейсе
                self._scapy_capture()
            else:
                # Использование raw socket для захвата всего трафика
                self._raw_socket_capture()
                
        except Exception as e:
            self.logger.error(f"Ошибка в потоке захвата: {e}")
    
    def _scapy_capture(self):
        """Захват с использованием Scapy"""
        def packet_handler(packet):
            if not self.running:
                return
            
            try:
                packet_data = bytes(packet)
                
                # Попытка записи в кольцевой буфер
                if not self.ring_buffer.write_packet(packet_data):
                    self.stats.packets_dropped += 1
                else:
                    self.stats.packets_captured += 1
                    self.stats.bytes_captured += len(packet_data)
                    
                    # Добавление в очередь обработки
                    try:
                        self.processing_queue.put_nowait(packet_data)
                    except queue.Full:
                        self.stats.packets_dropped += 1
                        
            except Exception as e:
                self.logger.error(f"Ошибка обработки пакета: {e}")
        
        # Запуск захвата Scapy
        scapy.sniff(
            iface=self.interface,
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: not self.running
        )
    
    def _raw_socket_capture(self):
        """Захват с использованием raw socket (только Linux)"""
        try:
            import platform
            if platform.system() == "Windows":
                self.logger.warning("Raw socket захват не поддерживается на Windows, используйте Scapy")
                return
                
            # Создание raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(1.0)
            
            while self.running:
                try:
                    packet_data, addr = sock.recvfrom(65535)
                    
                    # Запись в кольцевой буфер
                    if not self.ring_buffer.write_packet(packet_data):
                        self.stats.packets_dropped += 1
                    else:
                        self.stats.packets_captured += 1
                        self.stats.bytes_captured += len(packet_data)
                        
                        # Добавление в очередь обработки
                        try:
                            self.processing_queue.put_nowait(packet_data)
                        except queue.Full:
                            self.stats.packets_dropped += 1
                            
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Ошибка захвата: {e}")
                    
        except Exception as e:
            self.logger.error(f"Ошибка создания raw socket: {e}")
    
    def _processing_worker(self):
        """Рабочий поток обработки пакетов"""
        while self.running:
            try:
                # Получение пакета из очереди
                packet_data = self.processing_queue.get(timeout=1.0)
                
                # Обработка пакета
                metadata = self.packet_processor.process_packet(packet_data)
                if metadata:
                    # Вызов колбэков
                    for callback in self.packet_callbacks:
                        try:
                            callback(metadata, packet_data)
                        except Exception as e:
                            self.logger.error(f"Ошибка в колбэке: {e}")
                
                self.processing_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Ошибка в обработке: {e}")
    
    def _stats_worker(self):
        """Рабочий поток сбора статистики"""
        last_packets = 0
        last_time = time.time()
        
        while self.running:
            try:
                time.sleep(5)  # Обновление каждые 5 секунд
                
                current_time = time.time()
                current_packets = self.stats.packets_captured
                
                # Расчет скорости
                time_diff = current_time - last_time
                packet_diff = current_packets - last_packets
                
                if time_diff > 0:
                    self.stats.capture_rate = packet_diff / time_diff
                    self.stats.processing_rate = self.packet_processor.stats.packets_processed / time_diff
                
                self.stats.buffer_utilization = self.ring_buffer.get_utilization()
                self.stats.last_update = datetime.now()
                
                # Логирование статистики
                self.logger.info(
                    f"Захвачено: {self.stats.packets_captured}, "
                    f"Обработано: {self.stats.packets_processed}, "
                    f"Потеряно: {self.stats.packets_dropped}, "
                    f"Скорость: {self.stats.capture_rate:.1f} pps, "
                    f"Буфер: {self.stats.buffer_utilization:.1f}%"
                )
                
                last_packets = current_packets
                last_time = current_time
                
            except Exception as e:
                self.logger.error(f"Ошибка в статистике: {e}")
    
    def get_stats(self) -> CaptureStats:
        """Получение текущей статистики"""
        return self.stats
    
    def get_buffer_utilization(self) -> float:
        """Получение загрузки буфера"""
        return self.ring_buffer.get_utilization()

# Пример использования
if __name__ == "__main__":
    def packet_callback(metadata: PacketMetadata, packet_data: bytes):
        """Пример колбэка для обработки пакетов"""
        print(f"Пакет: {metadata.src_ip}:{metadata.src_port} -> "
              f"{metadata.dst_ip}:{metadata.dst_port} "
              f"({metadata.size} байт, протокол {metadata.protocol})")
    
    def anomaly_callback(anomaly_data: Dict):
        """Пример колбэка для обработки аномалий"""
        print(f"АНОМАЛИЯ: {anomaly_data}")
    
    # Создание и запуск захвата
    capture = HighPerformanceCapture(interface="eth0")
    capture.add_packet_callback(packet_callback)
    capture.add_anomaly_callback(anomaly_callback)
    
    try:
        capture.start_capture()
        
        # Работа в течение 60 секунд
        time.sleep(60)
        
    except KeyboardInterrupt:
        print("\nОстановка захвата...")
    finally:
        capture.stop_capture()
        
        # Вывод финальной статистики
        stats = capture.get_stats()
        print(f"\nФинальная статистика:")
        print(f"Захвачено пакетов: {stats.packets_captured}")
        print(f"Обработано пакетов: {stats.packets_processed}")
        print(f"Потеряно пакетов: {stats.packets_dropped}")
        print(f"Захвачено байт: {stats.bytes_captured}")
        print(f"Средняя скорость: {stats.capture_rate:.1f} pps")