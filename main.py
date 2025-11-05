# -*- coding: utf-8 -*-
import os
import sys
import time
import requests
import threading
import shutil
from Tkinter import *
import ttk
import tkFileDialog
import tkMessageBox
from collections import OrderedDict

# Конфигурация
API_KEY = "5dea5e24957590e6a47f9a989dbdaf9d9bd9ff2e92c1c082404ba2a8716264d7"
SCAN_INTERVAL = 30
LOGO_TEXT = "VirusTotal Scanner"
AUTHOR_TEXT = "Разработчик: Ваше Имя"
VERSION = "1.0"

class VirusTotalScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal File Scanner")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        
        # Переменные
        self.scanning = False
        self.files_queue = []
        self.scanned_files = {}
        self.current_file_index = 0
        self.clean_folder = ""
        
        self.setup_ui()
        
    def setup_ui(self):
        # Верхняя панель с лого и информацией
        header_frame = Frame(self.root, bg='#2c3e50', height=80)
        header_frame.pack(fill=X, side=TOP)
        header_frame.pack_propagate(0)
        
        logo_label = Label(header_frame, text=LOGO_TEXT, font=('Arial', 16, 'bold'), 
                          fg='white', bg='#2c3e50')
        logo_label.pack(pady=10)
        
        author_label = Label(header_frame, text=AUTHOR_TEXT, font=('Arial', 10), 
                           fg='#ecf0f1', bg='#2c3e50')
        author_label.pack()
        
        # Панель управления
        control_frame = Frame(self.root)
        control_frame.pack(fill=X, padx=10, pady=10)
        
        self.select_btn = Button(control_frame, text="Выбрать папку/файл", 
                                command=self.select_path, width=15)
        self.select_btn.grid(row=0, column=0, padx=5)
        
        self.scan_btn = Button(control_frame, text="Начать сканирование", 
                              command=self.toggle_scan, width=15, state=DISABLED)
        self.scan_btn.grid(row=0, column=1, padx=5)
        
        self.stop_btn = Button(control_frame, text="Остановить", 
                              command=self.stop_scan, width=15, state=DISABLED)
        self.stop_btn.grid(row=0, column=2, padx=5)
        
        self.progress_bar = ttk.Progressbar(control_frame, mode='determinate')
        self.progress_bar.grid(row=0, column=3, padx=5, sticky=EW)
        
        control_frame.columnconfigure(3, weight=1)
        
        # Статус бар
        self.status_var = StringVar()
        self.status_var.set("Готов к работе")
        status_bar = Label(self.root, textvariable=self.status_var, relief=SUNKEN, 
                          anchor=W, font=('Arial', 9))
        status_bar.pack(side=BOTTOM, fill=X)
        
        # Таблица с результатами
        self.setup_results_table()
        
    def setup_results_table(self):
        table_frame = Frame(self.root)
        table_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Создаем Treeview
        columns = ("filename", "size", "status", "progress", "result", "details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Настраиваем колонки
        self.tree.heading("filename", text="Имя файла")
        self.tree.heading("size", text="Размер")
        self.tree.heading("status", text="Статус")
        self.tree.heading("progress", text="Прогресс")
        self.tree.heading("result", text="Результат")
        self.tree.heading("details", text="Детали")
        
        self.tree.column("filename", width=200)
        self.tree.column("size", width=80)
        self.tree.column("status", width=100)
        self.tree.column("progress", width=80)
        self.tree.column("result", width=100)
        self.tree.column("details", width=200)
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(table_frame, orient=VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient=HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.tree.grid(row=0, column=0, sticky=NSEW)
        v_scroll.grid(row=0, column=1, sticky=NS)
        h_scroll.grid(row=1, column=0, sticky=EW)
        
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        
    def select_path(self):
        path = tkFileDialog.askdirectory(title="Выберите папку для сканирования")
        if path:
            self.target_path = path
            self.scan_btn.config(state=NORMAL)
            self.status_var.set("Выбрана папка: " + path)
            self.prepare_files_list(path)
            
    def prepare_files_list(self, path):
        self.files_queue = []
        self.tree.delete(*self.tree.get_children())
        
        if os.path.isfile(path):
            # Один файл
            file_size = self.get_file_size(os.path.getsize(path))
            item = self.tree.insert("", "end", values=(os.path.basename(path), file_size, 
                                                     "В очереди", "0%", "-", "-"))
            self.files_queue.append((path, item))
        else:
            # Папка с рекурсивным обходом
            for root_dir, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    try:
                        file_size = self.get_file_size(os.path.getsize(file_path))
                        item = self.tree.insert("", "end", values=(file, file_size, 
                                                                 "В очереди", "0%", "-", "-"))
                        self.files_queue.append((file_path, item))
                    except OSError:
                        continue
        
        self.total_files = len(self.files_queue)
        self.status_var.set("Найдено файлов: %d" % self.total_files)
        
    def get_file_size(self, size_bytes):
        """Конвертирует размер файла в читаемый формат"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return "%.1f %s" % (size_bytes, unit)
            size_bytes /= 1024.0
        return "%.1f %s" % (size_bytes, 'TB')
    
    def toggle_scan(self):
        if not self.scanning:
            self.start_scan()
        else:
            self.stop_scan()
            
    def start_scan(self):
        if not self.files_queue:
            tkMessageBox.showwarning("Предупреждение", "Нет файлов для сканирования!")
            return
            
        self.scanning = True
        self.scan_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.select_btn.config(state=DISABLED)
        
        # Создаем папку для чистых файлов
        base_path = self.target_path if os.path.isdir(self.target_path) else os.path.dirname(self.target_path)
        base_name = os.path.basename(self.target_path.rstrip('/\\'))
        self.clean_folder = os.path.join(base_path, base_name + "_Clean")
        
        if not os.path.exists(self.clean_folder):
            os.makedirs(self.clean_folder)
        
        self.current_file_index = 0
        self.progress_bar['maximum'] = self.total_files
        self.progress_bar['value'] = 0
        
        # Запускаем сканирование в отдельном потоке
        scan_thread = threading.Thread(target=self.scan_files)
        scan_thread.daemon = True
        scan_thread.start()
        
    def stop_scan(self):
        self.scanning = False
        self.scan_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.select_btn.config(state=NORMAL)
        self.status_var.set("Сканирование остановлено")
        
    def scan_files(self):
        for file_path, item in self.files_queue:
            if not self.scanning:
                break
                
            self.current_file_index += 1
            self.status_var.set("Сканирование файла %d из %d" % (self.current_file_index, self.total_files))
            
            # Обновляем статус в таблице
            self.tree.set(item, "status", "Сканируется...")
            self.tree.set(item, "progress", "0%")
            self.root.update()
            
            # Сканируем файл
            result = self.scan_file(file_path, item)
            
            # Обновляем прогресс
            self.progress_bar['value'] = self.current_file_index
            progress_percent = (self.current_file_index * 100) // self.total_files
            self.progress_bar.configure(value=self.current_file_index)
            
            # Копируем чистые файлы
            if result == "clean":
                self.copy_clean_file(file_path)
            
            # Задержка между сканированиями
            if self.current_file_index < self.total_files:
                for i in range(SCAN_INTERVAL):
                    if not self.scanning:
                        break
                    time.sleep(1)
                    remaining = SCAN_INTERVAL - i
                    self.tree.set(item, "progress", "Ожидание %ds" % remaining)
                    self.root.update()
        
        self.scanning = False
        self.scan_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.select_btn.config(state=NORMAL)
        self.status_var.set("Сканирование завершено")
        
    def scan_file(self, file_path, item):
        try:
            # Обновляем статус
            self.tree.set(item, "status", "Загрузка на VirusTotal")
            self.tree.set(item, "progress", "25%")
            self.root.update()
            
            # Загружаем файл
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                headers = {'x-apikey': API_KEY}
                response = requests.post('https://www.virustotal.com/api/v3/files', 
                                       files=files, headers=headers)
            
            if response.status_code != 200:
                self.tree.set(item, "status", "Ошибка загрузки")
                self.tree.set(item, "result", "Ошибка")
                self.tree.set(item, "details", "Код: %d" % response.status_code)
                return "error"
            
            # Получаем ID анализа
            analysis_id = response.json()['data']['id']
            
            # Проверяем результат
            self.tree.set(item, "status", "Анализ...")
            self.tree.set(item, "progress", "50%")
            self.root.update()
            
            # Ждем завершения анализа
            analysis_url = 'https://www.virustotal.com/api/v3/analyses/{}'.format(analysis_id)
            while True:
                if not self.scanning:
                    return "stopped"
                    
                time.sleep(5)
                analysis_response = requests.get(analysis_url, headers=headers)
                
                if analysis_response.status_code != 200:
                    self.tree.set(item, "status", "Ошибка анализа")
                    self.tree.set(item, "result", "Ошибка")
                    self.tree.set(item, "details", "Анализ не удался")
                    return "error"
                
                analysis_data = analysis_response.json()
                status = analysis_data['data']['attributes']['status']
                
                if status == 'completed':
                    break
                
                self.tree.set(item, "progress", "Ожидание...")
                self.root.update()
            
            # Получаем результаты
            self.tree.set(item, "status", "Завершено")
            self.tree.set(item, "progress", "100%")
            self.root.update()
            
            stats = analysis_data['data']['attributes']['stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious > 0:
                self.tree.set(item, "result", "Обнаружено")
                # Получаем детали обнаружений
                results = analysis_data['data']['attributes']['results']
                detections = []
                for engine, result in results.items():
                    if result.get('category') == 'malicious':
                        detections.append("%s: %s" % (engine, result.get('result', 'Unknown')))
                
                details = ", ".join(detections[:3])  # Показываем первые 3 обнаружения
                if len(detections) > 3:
                    details += " и еще %d" % (len(detections) - 3)
                
                self.tree.set(item, "details", details)
                return "malicious"
            elif suspicious > 0:
                self.tree.set(item, "result", "Подозрительный")
                self.tree.set(item, "details", "Подозрительных: %d" % suspicious)
                return "suspicious"
            else:
                self.tree.set(item, "result", "Чистый")
                self.tree.set(item, "details", "Без обнаружений")
                return "clean"
                
        except Exception as e:
            self.tree.set(item, "status", "Ошибка")
            self.tree.set(item, "result", "Ошибка")
            self.tree.set(item, "details", str(e))
            return "error"
    
    def copy_clean_file(self, file_path):
        """Копирует чистый файл в папку _Clean"""
        try:
            if os.path.isfile(self.target_path):
                # Если сканировали один файл
                dest_path = os.path.join(self.clean_folder, os.path.basename(file_path))
            else:
                # Если сканировали папку - сохраняем структуру папок
                relative_path = os.path.relpath(file_path, self.target_path)
                dest_path = os.path.join(self.clean_folder, relative_path)
                
                # Создаем необходимые папки
                dest_dir = os.path.dirname(dest_path)
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)
            
            shutil.copy2(file_path, dest_path)
        except Exception as e:
            print("Ошибка копирования файла %s: %s" % (file_path, str(e)))

def main():
    root = Tk()
    app = VirusTotalScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
