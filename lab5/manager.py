#!/usr/bin/env python3
"""Лабораторная работа №5. Комплексное обеспечение безопасности менеджера учётных записей.

Графический интерфейс (tkinter) к хранилищу storage.py: просмотр, добавление, изменение
и удаление учётных записей в текстовом файле БД (пароли — только в виде солёного хэша),
проверка целостности БД по эталонной хэш-сумме, шифрование и расшифрование файлов БД,
хэш-суммы и журнала (AES-256-CBC, отдельный ключ для каждого файла) и журнал событий
с датой и временем операций.

Только стандартная библиотека. Запуск: python3 manager.py [папка данных]
Автоматическая проверка подсистем без GUI: python3 storage.py
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
from storage import (DATA_DIR, FILES, ROLES, TITLES, ManagerError, Store,   # noqa: E402
                     check_login, check_new_password, first_upper)


class Dialog(simpledialog.Dialog):
    """Модальное окно с русскими кнопками (simpledialog.Dialog даёт OK/Cancel)."""

    def buttonbox(self):
        box = ttk.Frame(self)
        ttk.Button(box, text="ОК", width=10, command=self.ok, default="active").pack(side="left", padx=5, pady=5)
        ttk.Button(box, text="Отмена", width=10, command=self.cancel).pack(side="left", padx=5, pady=5)
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()


class PasswordDialog(Dialog):
    """Ввод пароля (ключа файла или пароля пользователя); confirm=True — с полем повтора."""

    def __init__(self, parent, title, prompt, confirm=False):
        self.prompt, self.confirm, self.result = prompt, confirm, None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text=self.prompt).grid(row=0, column=0, columnspan=2, sticky="w", padx=4, pady=(4, 6))
        ttk.Label(master, text="Пароль:").grid(row=1, column=0, sticky="e", padx=4, pady=3)
        self.e_pass = ttk.Entry(master, width=30, show="•")
        self.e_pass.grid(row=1, column=1, padx=4, pady=3)
        if self.confirm:
            ttk.Label(master, text="Повтор пароля:").grid(row=2, column=0, sticky="e", padx=4, pady=3)
            self.e_pass2 = ttk.Entry(master, width=30, show="•")
            self.e_pass2.grid(row=2, column=1, padx=4, pady=3)
        return self.e_pass

    def validate(self):
        if not self.e_pass.get():
            messagebox.showerror("Ошибка", "Пароль не может быть пустым.", parent=self)
            return False
        if self.confirm and self.e_pass.get() != self.e_pass2.get():
            messagebox.showerror("Ошибка", "Пароли не совпадают.", parent=self)
            return False
        return True

    def apply(self):
        self.result = self.e_pass.get()


class AccountDialog(Dialog):
    """Окно добавления/изменения учётной записи."""

    def __init__(self, parent, title, login="", editing=False):
        self.login, self.editing, self.result = login, editing, None
        super().__init__(parent, title)

    def body(self, master):
        hint = "Новый пароль (пусто — не менять)" if self.editing else "Пароль"
        ttk.Label(master, text="Логин:").grid(row=0, column=0, sticky="e", padx=4, pady=3)
        ttk.Label(master, text=hint + ":").grid(row=1, column=0, sticky="e", padx=4, pady=3)
        ttk.Label(master, text="Повтор пароля:").grid(row=2, column=0, sticky="e", padx=4, pady=3)
        self.e_login = ttk.Entry(master, width=30)
        self.e_pass = ttk.Entry(master, width=30, show="•")
        self.e_pass2 = ttk.Entry(master, width=30, show="•")
        self.e_login.insert(0, self.login)
        for row, entry in enumerate((self.e_login, self.e_pass, self.e_pass2)):
            entry.grid(row=row, column=1, padx=4, pady=3)
        return self.e_login

    def validate(self):
        try:
            check_login(self.e_login.get())
            if self.e_pass.get() or not self.editing:
                check_new_password(self.e_pass.get())
            if self.e_pass.get() != self.e_pass2.get():
                raise ManagerError("пароли не совпадают")
        except ManagerError as exc:
            messagebox.showerror("Ошибка", first_upper(str(exc)), parent=self)
            return False
        return True

    def apply(self):
        self.result = (self.e_login.get(), self.e_pass.get())


class App(tk.Tk):
    """Главное окно: список учётных записей, шифрование файлов, целостность БД, журнал."""

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.title("Менеджер учётных записей — лабораторная работа №5")
        self.minsize(820, 640)
        self.state_labels, self.hash_vars = {}, {}
        self.status = tk.StringVar(value=f"Папка данных: {store.dir}")
        self.build()
        self.refresh()

    # --- построение окна
    def build(self):
        pad = {"padx": 6, "pady": 4}
        frame_acc = ttk.LabelFrame(self, text="Учётные записи (accounts.txt)")
        frame_acc.pack(fill="both", expand=True, **pad)
        columns = ("login", "salt", "hash")
        self.tree = ttk.Treeview(frame_acc, columns=columns, show="headings", height=8)
        for col, title, width in (("login", "Логин", 200), ("salt", "Соль (hex)", 230), ("hash", "Хэш пароля PBKDF2-SHA256 (hex)", 360)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame_acc, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=4)
        scroll.pack(side="left", fill="y", pady=4)
        buttons = ttk.Frame(frame_acc)
        buttons.pack(side="left", fill="y", padx=6, pady=4)
        for text, cmd in (("Добавить", self.add), ("Изменить", self.edit), ("Удалить", self.delete),
                          ("Проверить пароль", self.verify), ("Обновить", self.refresh)):
            ttk.Button(buttons, text=text, command=cmd, width=18).pack(fill="x", pady=2)

        frame_files = ttk.LabelFrame(self, text="Шифрование файлов (AES-256-CBC, отдельный ключ для каждого файла)")
        frame_files.pack(fill="x", **pad)
        for row, role in enumerate(ROLES):
            title = f"{TITLES[role][0].upper()}{TITLES[role][1:]} — {FILES[role]}:"
            ttk.Label(frame_files, text=title, width=36).grid(row=row, column=0, sticky="w", padx=6, pady=3)
            self.state_labels[role] = ttk.Label(frame_files, text="", width=22)
            self.state_labels[role].grid(row=row, column=1, sticky="w", padx=6)
            ttk.Button(frame_files, text="Зашифровать", command=lambda r=role: self.encrypt(r)).grid(row=row, column=2, padx=3, pady=2)
            ttk.Button(frame_files, text="Расшифровать", command=lambda r=role: self.decrypt(r)).grid(row=row, column=3, padx=3, pady=2)

        frame_int = ttk.LabelFrame(self, text="Целостность БД (SHA-256, эталон в accounts.hash)")
        frame_int.pack(fill="x", **pad)
        for row, (key, title) in enumerate((("stored", "Эталонная хэш-сумма:"), ("actual", "Актуальная хэш-сумма:"))):
            ttk.Label(frame_int, text=title, width=22).grid(row=row, column=0, sticky="w", padx=6, pady=2)
            self.hash_vars[key] = tk.StringVar()
            ttk.Label(frame_int, textvariable=self.hash_vars[key], font=("Courier", 11)).grid(row=row, column=1, sticky="w", padx=6)
        ttk.Button(frame_int, text="Сохранить хэш-сумму", command=self.save_hash).grid(row=0, column=2, padx=6, pady=2, sticky="e")
        ttk.Button(frame_int, text="Проверить целостность", command=self.check).grid(row=1, column=2, padx=6, pady=2, sticky="e")
        frame_int.columnconfigure(1, weight=1)

        frame_log = ttk.LabelFrame(self, text="Журнал событий (events.log)")
        frame_log.pack(fill="both", expand=True, **pad)
        self.log_text = tk.Text(frame_log, height=9, font=("Courier", 11), state="disabled", wrap="none")
        log_y = ttk.Scrollbar(frame_log, orient="vertical", command=self.log_text.yview)
        log_x = ttk.Scrollbar(frame_log, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=log_y.set, xscrollcommand=log_x.set)
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=(4, 0))
        log_y.grid(row=0, column=1, sticky="ns", pady=(4, 0))
        log_x.grid(row=1, column=0, sticky="ew", padx=(6, 0), pady=(0, 4))
        frame_log.rowconfigure(0, weight=1)
        frame_log.columnconfigure(0, weight=1)

        ttk.Label(self, textvariable=self.status, anchor="w", relief="sunken").pack(fill="x", padx=6, pady=(0, 6))

    # --- обновление состояния
    def refresh(self, select=None):
        """Перечитывает файлы с диска; select — логин, который нужно выделить в списке."""
        for role in ROLES:
            try:
                data = self.store.read(role)
                if data is None:
                    text = "файл отсутствует"
                elif self.store.is_encrypted(role):
                    text = "ЗАШИФРОВАН"
                else:
                    text = f"открыт, {len(data)} байт"
            except ManagerError as exc:
                text = f"не удалось прочитать: {exc}"
            self.state_labels[role].configure(text=text)
        focused = self.tree.focus()
        selected = select or (self.tree.item(focused, "values")[0] if focused else None)   # сохраняем выбор
        self.tree.delete(*self.tree.get_children())
        try:
            for login, salt, digest in self.store.load_accounts():
                item = self.tree.insert("", "end", values=(login, salt, digest))
                if login == selected:
                    self.tree.focus(item)
                    self.tree.selection_set(item)
        except ManagerError as exc:
            short = "(БД зашифрована)" if self.state_labels["db"].cget("text") == "ЗАШИФРОВАН" else f"({exc})"
            self.tree.insert("", "end", values=(short, "", ""))
        for key, role, getter in (("stored", "hash", self.store.stored_hash), ("actual", "db", self.store.db_hash)):
            try:
                self.hash_vars[key].set(getter() or "— не сохранена —")
            except ManagerError as exc:
                self.hash_vars[key].set("(файл зашифрован)" if self.state_labels[role].cget("text") == "ЗАШИФРОВАН" else f"({exc})")
        try:
            text = "(журнал зашифрован)" if self.store.is_encrypted("log") else "\n".join(self.store.log_lines())
        except ManagerError as exc:
            text = f"(не удалось прочитать журнал: {exc})"
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def selected_login(self):
        item = self.tree.focus()
        if not item or not self.tree.item(item, "values")[1]:
            raise ManagerError("выберите учётную запись в списке")
        return self.tree.item(item, "values")[0]

    def guarded(self, action, done=None, select=None):
        """Выполняет действие, показывает ошибки и обновляет окно (select — логин для выделения)."""
        try:
            result = action()
        except (ManagerError, OSError) as exc:
            messagebox.showerror("Ошибка", first_upper(str(exc)), parent=self)
            self.status.set(f"Ошибка: {exc}")
            self.refresh()
            return
        self.refresh(select)
        if done:
            self.status.set(done if isinstance(done, str) else done(result))
        return result

    def ask_password(self, role, verb, confirm=False):
        return PasswordDialog(self, "Ключ файла", f"{verb} файл {FILES[role]} ({TITLES[role]}).", confirm).result

    # --- команды
    def add(self):
        try:
            missing = self.store.read("db") is None
        except ManagerError:
            missing = False
        if missing:
            if messagebox.askyesno("БД отсутствует", f"Файл {FILES['db']} не найден. Создать пустую БД и сохранить её хэш-сумму?", parent=self):
                self.guarded(self.store.create_db, "Создана пустая БД")
            return
        dlg = AccountDialog(self, "Новая учётная запись")
        if dlg.result:
            login, password = dlg.result
            self.guarded(lambda: self.store.add_account(login, password), f"Добавлена учётная запись «{login}»")

    def edit(self):
        try:
            login = self.selected_login()
        except ManagerError as exc:
            return messagebox.showinfo("Изменение", first_upper(str(exc)), parent=self)
        dlg = AccountDialog(self, f"Изменение учётной записи «{login}»", login, editing=True)
        if dlg.result:
            new_login, new_password = dlg.result
            self.guarded(lambda: self.store.update_account(login, new_login, new_password),
                         f"Изменена учётная запись «{login}»", select=new_login)

    def delete(self):
        try:
            login = self.selected_login()
        except ManagerError as exc:
            return messagebox.showinfo("Удаление", first_upper(str(exc)), parent=self)
        if messagebox.askyesno("Удаление", f"Удалить учётную запись «{login}»?", parent=self):
            self.guarded(lambda: self.store.delete_account(login), f"Удалена учётная запись «{login}»")

    def verify(self):
        try:
            login = self.selected_login()
        except ManagerError as exc:
            return messagebox.showinfo("Проверка пароля", first_upper(str(exc)), parent=self)
        password = PasswordDialog(self, "Проверка пароля", f"Введите пароль пользователя «{login}».").result
        if password is None:
            return
        ok = self.guarded(lambda: self.store.verify_password(login, password))
        if ok is not None:
            (messagebox.showinfo if ok else messagebox.showwarning)(
                "Проверка пароля", f"Пароль пользователя «{login}» " + ("верный." if ok else "НЕВЕРНЫЙ."), parent=self)
            self.status.set(f"Проверка пароля «{login}»: " + ("верный" if ok else "неверный"))

    def save_hash(self):
        self.guarded(self.store.save_hash, "Эталонная хэш-сумма БД сохранена")

    def check(self):
        result = self.guarded(self.store.check_integrity)
        if result is None:
            return
        ok, expected, actual = result
        if ok:
            messagebox.showinfo("Целостность", f"БД в целостности.\n\nХэш-сумма: {actual}", parent=self)
        else:
            messagebox.showwarning("Целостность", f"БД была изменена извне!\n\nЭталон:     {expected}\nАктуальная: {actual}", parent=self)
        self.status.set("Проверка целостности: " + ("БД в целостности" if ok else "БД была изменена извне"))

    def encrypt(self, role):
        password = self.ask_password(role, "Зашифровать", confirm=True)
        if password is not None:
            self.guarded(lambda: self.store.encrypt_file(role, password), f"Файл {FILES[role]} зашифрован")

    def decrypt(self, role):
        password = self.ask_password(role, "Расшифровать")
        if password is None:
            return
        self.guarded(lambda: self.store.decrypt_file(role, password), f"Файл {FILES[role]} расшифрован")


def main(argv):
    data_dir = next((a for a in argv[1:] if not a.startswith("-")), DATA_DIR)
    try:
        app = App(Store(data_dir))
    except ManagerError as exc:
        tk.Tk().withdraw()
        messagebox.showerror("Менеджер учётных записей", first_upper(str(exc)))
        sys.exit(1)
    app.mainloop()


if __name__ == "__main__":
    main(sys.argv)
