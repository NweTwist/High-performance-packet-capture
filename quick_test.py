#!/usr/bin/env python3
"""
Быстрый тест для high_performance_capture.py
"""

import sys
import time
from pathlib import Path

# Импорт модулей
try:
    from test_pcap_capture import PcapTester
except ImportError:
    print("Ошибка импорта test_pcap_capture.py")
    sys.exit(1)

def quick_test(pcap_file: str):
    """Быстрый тест с минимальным выводом"""
    print(f"🧪 Быстрый тест с файлом: {pcap_file}")
    
    try:
        tester = PcapTester(pcap_file)
        tester.load_pcap()
        
        print(f"📦 Загружено {len(tester.packets)} пакетов")
        print("🚀 Запуск теста...")
        
        start_time = time.time()
        tester.simulate_capture(delay=0)  # Без задержек
        test_time = time.time() - start_time
        
        # Краткая статистика
        processed = len(tester.processed_packets)
        total = len(tester.packets)
        success_rate = (processed / total) * 100 if total > 0 else 0
        
        print(f"\n✅ Результат: {processed}/{total} пакетов ({success_rate:.1f}%)")
        print(f"⏱️  Время: {test_time:.2f}s")
        print(f"🚀 Скорость: {total/test_time:.0f} пакетов/сек")
        
        if success_rate >= 95:
            print("🎉 ТЕСТ ПРОЙДЕН!")
            return True
        else:
            print("❌ ТЕСТ НЕ ПРОЙДЕН!")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка теста: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python quick_test.py <pcap_file>")
        print("Пример: python quick_test.py sample.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    if not Path(pcap_file).exists():
        print(f"❌ Файл не найден: {pcap_file}")
        sys.exit(1)
    
    success = quick_test(pcap_file)
    sys.exit(0 if success else 1)