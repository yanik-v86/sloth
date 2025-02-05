import tkinter as tk
import threading
import datetime
import requests
import base64
import json
import os
import io

from tkinter import ttk, scrolledtext, messagebox, filedialog
from PIL import Image, ImageTk

class OllamaReportApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sloth is ollama report app")
        self.settings = {
            "server_address": "http://localhost:11434",
            "default_prompt": "{start}  Create a review about {fio} about his {work_qualities} work done in {module} based on what was done in {what_done} be sure to specify the qualities of the resident {user_qualities}  {end} ",
            "user_qualities": ["Performance", "Responsibility", "Attentive", "Creative", "Enthusiastic", "Optimistic"],
            "work_qualities": ["Fascinating", "Inspiring", "Excellent"]
        }
        self.load_settings()

        self.style = ttk.Style()
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('TLabel', font=('Arial', 10))
        self.style.configure('TEntry', font=('Arial', 10))
        self.style.configure('TCheckbutton', font=('Arial', 10))
        self.style.configure('TCombobox', font=('Arial', 10))

        input_frame = ttk.LabelFrame(root, text="Data for the report", padding=10)
        input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")

        ttk.Label(input_frame, text="Model:").grid(row=0, column=0, sticky="e", pady=5, padx=10)
        self.model_var = tk.StringVar()
        self.model_combo = ttk.Combobox(input_frame, textvariable=self.model_var, width=40)
        self.model_combo.grid(row=0, column=1, pady=5, padx=0)
        self.update_model_list()  # Инициализируем список моделей

        ttk.Label(input_frame, text="Name:").grid(row=1, column=0, sticky="e", pady=5, padx=10)
        self.fio_entry = ttk.Entry(input_frame, width=40)
        self.fio_entry.grid(row=1, column=1, pady=5, padx=0)

        self.user_labelframe = ttk.LabelFrame(input_frame, text="Personal qualities", padding=10)
        self.user_labelframe.grid(row=2, column=1, padx=0, pady=10, sticky="nswe")

        self.qualities = {quality: tk.BooleanVar() for quality in self.settings["user_qualities"]}

        qualities_frame = ttk.Frame(self.user_labelframe)
        qualities_frame.grid(row=2, column=1, pady=5, sticky="w")
        for i, (quality, var) in enumerate(self.qualities.items()):
            ttk.Checkbutton(qualities_frame, text=quality, variable=var).grid(row=i // 2, column=i % 2, sticky="w")

        ttk.Label(input_frame, text="Module:").grid(row=3, column=0,  sticky="e", pady=5, padx=10)
        self.module_entry = ttk.Entry(input_frame, width=40)
        self.module_entry.grid(row=3, column=1, pady=5)

        ttk.Label(input_frame, text="What's done:").grid(row=4, column=0,  sticky="e", pady=5, padx=10)
        self.what_done_text = scrolledtext.ScrolledText(input_frame, width=37, height=5, wrap=tk.WORD)
        self.what_done_text.grid(row=4, column=1, pady=5, sticky="we")


        self.work_labelframe = ttk.LabelFrame(input_frame, text="Quality of work", padding=10)
        self.work_labelframe.grid(row=5, column=1, padx=0, pady=10, sticky="nswe")

        self.work_qualities = {quality2: tk.BooleanVar() for quality2 in self.settings["work_qualities"]}

        qualities_frame2 = ttk.Frame(self.work_labelframe)
        qualities_frame2.grid(row=7, column=1, pady=5, sticky="w")
        for i, (quality2, var) in enumerate(self.work_qualities.items()):
            ttk.Checkbutton(qualities_frame2, text=quality2, variable=var).grid(row=i // 2, column=i % 2, sticky="w")

        output_frame = ttk.LabelFrame(root, text="Feedback", padding=10)
        output_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nswe")

        ttk.Label(output_frame, text="Beginning:").grid(row=1, column=0,   sticky="e", pady=5, padx=10)
        self.start_entry = ttk.Entry(output_frame, width=50)
        self.start_entry.grid(row=1, column=1, pady=5)

        ttk.Label(output_frame, text="Prompt:").grid(row=2, column=0,  sticky="e", pady=5, padx=10)
        self.prompt_text = scrolledtext.ScrolledText(output_frame, width=50, height=7, wrap=tk.WORD)
        self.prompt_text.grid(row=2, column=1, padx=10, pady=10, sticky="we")
        self.prompt_text.insert(tk.END, self.settings["default_prompt"])

        ttk.Label(output_frame, text="The end:").grid(row=3, column=0,  sticky="e", pady=5, padx=10)
        self.end_entry = ttk.Entry(output_frame, width=50)
        self.end_entry.grid(row=3, column=1, pady=5)

        ttk.Button(output_frame, text="Generate a review", command=self.generate_report).grid(row=4, column=1, padx=10, pady=10, sticky="we")

        self.progress_bar = ttk.Progressbar(output_frame, orient="horizontal",
                                            length=200, mode="indeterminate")
        self.progress_bar.grid(row=5, column=1, sticky="we", padx=10)
        self.progress_bar.grid_remove()

        ttk.Label(output_frame, text="Feedback:").grid(row=6, column=0,  sticky="e", pady=5, padx=5)
        self.result_text = scrolledtext.ScrolledText(output_frame, width=50, height=10, wrap=tk.WORD)
        self.result_text.grid(row=6, column=1, padx=10, pady=10, sticky="we")
        self.result_text.config(state=tk.DISABLED)

        menubar = tk.Menu(root)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Settings", command=self.open_settings_window)
        menubar.add_cascade(label="Menu", menu=settings_menu)
        root.config(menu=menubar)

        root.columnconfigure(0, weight=1)
        root.rowconfigure(3, weight=1)

  
    def update_result(self, result):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", result)
        self.result_text.config(state="disabled")

  
    def show_loading(self):
        self.progress_bar.grid()
        self.progress_bar.start(10)

  
    def hide_loading(self):
        self.progress_bar.stop()
        self.progress_bar.grid_remove()

  
    def load_settings(self):

        settings_path = "settings.json"
        if os.path.exists(settings_path):
            try:
                with open(settings_path, "r") as f:
                    self.settings = json.load(f)
            except json.JSONDecodeError:
                 self.show_error(f"Error loading settings from {settings_path}")
            except Exception as e:
                 self.show_error(f"Error when working with the file {settings_path}: {e}")

  
    def save_settings(self):

        settings_path = "settings.json"
        try:
            with open(settings_path, "w") as f:
                 json.dump(self.settings, f, indent=4)
        except Exception as e:
            self.show_error(f"Error when saving settings in {settings_path}: {e}")

  
    def open_settings_window(self):

        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")

        ttk.Label(settings_window, text="Server address:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.server_entry = ttk.Entry(settings_window, width=40)
        self.server_entry.insert(0, self.settings["server_address"])
        self.server_entry.grid(row=0, column=1, padx=10, pady=5)


        ttk.Label(settings_window, text="Default prompt:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.default_prompt_text = scrolledtext.ScrolledText(settings_window, width=37, height=5, wrap=tk.WORD)
        self.default_prompt_text.grid(row=1, column=1, padx=10, pady=5)
        self.default_prompt_text.insert(tk.END, self.settings["default_prompt"])


        ttk.Label(settings_window, text="Personal qualities:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.user_qualities_text = scrolledtext.ScrolledText(settings_window, width=37, height=5, wrap=tk.WORD)
        self.user_qualities_text.grid(row=2, column=1, padx=10, pady=5)
        self.user_qualities_text.insert(tk.END, "\n".join(self.settings["user_qualities"]))


        ttk.Label(settings_window, text="Quality of work:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.work_qualities_text = scrolledtext.ScrolledText(settings_window, width=37, height=5, wrap=tk.WORD)
        self.work_qualities_text.grid(row=3, column=1, padx=10, pady=5)
        self.work_qualities_text.insert(tk.END, "\n".join(self.settings["work_qualities"]))

        ttk.Button(settings_window, text="Save", command=self.save_settings_from_window).grid(row=4, column=0, padx=10, pady=10, sticky="e")
        ttk.Button(settings_window, text="Cancel", command=settings_window.destroy).grid(row=4, column=1, padx=10, pady=10, sticky="w")

        settings_window.columnconfigure(1, weight=1)


    def save_settings_from_window(self):

        self.settings["server_address"] = self.server_entry.get()
        self.settings["default_prompt"] = self.default_prompt_text.get("1.0", tk.END).strip()
        self.settings["user_qualities"] = [line.strip() for line in self.user_qualities_text.get("1.0", tk.END).splitlines() if line.strip()]
        self.settings["work_qualities"] = [line.strip() for line in self.work_qualities_text.get("1.0", tk.END).splitlines() if line.strip()]
        self.save_settings()
        self.update_qualities_checkboxes(self.user_labelframe)
        self.update_work_qualities_checkboxes(self.work_labelframe)
        self.prompt_text.delete("1.0", tk.END)
        self.prompt_text.insert(tk.END, self.settings["default_prompt"])

        messagebox.showinfo("Success", "The settings are saved.")
        self.update_model_list()


    def update_qualities_checkboxes(self, target_frame):
        for widget in target_frame.winfo_children():
            widget.destroy()

        self.qualities = {quality: tk.BooleanVar() for quality in self.settings["user_qualities"]}
        for i, (quality, var) in enumerate(self.qualities.items()):
            ttk.Checkbutton(target_frame, text=quality, variable=var).grid(row=i // 2, column=i % 2, sticky="w")


    def update_work_qualities_checkboxes(self, target_frame):
        for widget in target_frame.winfo_children():
            widget.destroy()
        self.work_qualities = {work_quality: tk.BooleanVar() for work_quality in self.settings["work_qualities"]}
        for i, (work_quality, var) in enumerate(self.work_qualities.items()):
            ttk.Checkbutton(target_frame, text=work_quality, variable=var).grid(row=i // 2, column=i % 2, sticky="w")


    def update_model_list(self):
        models = self.get_ollama_models()
        if models:
            model_names = [model['name'] for model in models]
            self.model_combo['values'] = model_names
            if model_names:
              self.model_var.set(model_names[0])
        else:
            self.show_error("Couldn't get a list of Ollama models. Make sure that Ollama is running")
            self.model_combo['values'] = []


    def get_ollama_models(self):
        try:
            response = requests.get(f"{self.settings['server_address']}/api/tags")
            response.raise_for_status()
            data = response.json()
            if 'models' in data:
                return data['models']
            else:
                return []
        except requests.exceptions.RequestException as e:
             print(f"Error when requesting the Ollama API: {e}")
             return None
        except Exception as e:
             self.show_error(f"Unknown error: {e}")
             return None

    def generate_report(self):
        selected_model = self.model_var.get()
        fio = self.fio_entry.get()
        module = self.module_entry.get()
        what_done = self.what_done_text.get("1.0", tk.END).strip()
        start = self.start_entry.get()
        end = self.end_entry.get()
        prompt = self.prompt_text.get("1.0", tk.END).strip()
        selected_qualities = [quality for quality, var in self.qualities.items() if var.get()]
        qualities_string = ", ".join(selected_qualities)
        selected_work_qualities = [work_quality for work_quality, var in self.work_qualities.items() if var.get()]
        work_qualities_string = ", ".join(selected_work_qualities)
        full_prompt = prompt.format(fio=fio, module=module, what_done=what_done, start=start, end=end, user_qualities=qualities_string, work_qualities=work_qualities_string)
        print(full_prompt)

        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state=tk.DISABLED)
        threading.Thread(target=self.send_ollama_request, args=(selected_model, full_prompt)).start()

    def send_ollama_request(self, model_name, prompt):

        def stream_generator():
            url = f"{self.settings['server_address']}/api/chat"
            headers = {"Content-Type": "application/json"}
            data = {
                "model": model_name,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "stream": True
            }
            try:
                self.show_loading()

                response = requests.post(url, headers=headers, data=json.dumps(data), stream=True)
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        try:
                            json_data = json.loads(line)
                            if json_data and 'message' in json_data:
                                yield json_data['message']['content']
                        except json.JSONDecodeError:
                            continue
            except requests.exceptions.RequestException as e:
                self.show_error(f"Error when requesting the Ollama API: {e}")
                return
            except Exception as e:
                 self.show_error(f"Unknown error: {e}")
                 return
            finally:
                self.root.after(0, self.hide_loading)

        stream = stream_generator()
        if stream:
            self.result_text.config(state=tk.NORMAL)
            try:
                 for chunk in stream:
                     self.result_text.insert(tk.END, chunk)
                     self.result_text.see(tk.END)
                     self.root.update()
            except Exception as e:
                 self.show_error(f"An error occurred while processing data from OLLAMA: {e}")
            finally:
                  self.result_text.config(state=tk.DISABLED)
        else:
                self.show_error("Couldn't get a response from the model")



    def show_error(self, message):
         messagebox.showerror("Error", message)


if __name__ == "__main__":
    root = tk.Tk()
    app = OllamaReportApp(root)
    try:
        base64_data = '''/9j/4AAQSkZJRgABAQEASABIAAD/4QCuRXhpZgAASUkqAAgAAAAHABIBAwABAAAAAQAAABoBBQABAAAAYgAAABsBBQABAAAAagAAACgBAwABAAAAAgAAADEBAgANAAAAcgAAADIBAgAUAAAAgAAAAGmHBAABAAAAlAAAAAAAAABIAAAAAQAAAEgAAAABAAAAR0lNUCAyLjEwLjM4AAAyMDI1OjAyOjA0IDE1OjQwOjQwAAEAAaADAAEAAAABAAAAAAAAAP/hDM9odHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IlhNUCBDb3JlIDQuNC4wLUV4aXYyIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6R0lNUD0iaHR0cDovL3d3dy5naW1wLm9yZy94bXAvIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOkRvY3VtZW50SUQ9ImdpbXA6ZG9jaWQ6Z2ltcDpkOGRlZWJkYi00ZjBiLTQxOTktYjFkZC1mOWY5MDEyYzk4M2UiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6NTRmODdlMDktZjc1Ny00Zjk2LTgxODgtODdkMTljY2I1NDY3IiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6YWRmYzExOWEtNWU2Ny00N2VmLWE3NWQtMjRlMzI3MWY3M2UxIiBkYzpGb3JtYXQ9ImltYWdlL2pwZWciIEdJTVA6QVBJPSIyLjAiIEdJTVA6UGxhdGZvcm09IkxpbnV4IiBHSU1QOlRpbWVTdGFtcD0iMTczODY3Mjg0Mzg0MTA5OCIgR0lNUDpWZXJzaW9uPSIyLjEwLjM4IiB4bXA6Q3JlYXRvclRvb2w9IkdJTVAgMi4xMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyNTowMjowNFQxNTo0MDo0MCswMzowMCIgeG1wOk1vZGlmeURhdGU9IjIwMjU6MDI6MDRUMTU6NDA6NDArMDM6MDAiPiA8eG1wTU06SGlzdG9yeT4gPHJkZjpTZXE+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJzYXZlZCIgc3RFdnQ6Y2hhbmdlZD0iLyIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDo5MmUwNWU3OS1iODViLTQzNzItOGQyMS03OGVlZGIyYTY5NTMiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoTGludXgpIiBzdEV2dDp3aGVuPSIyMDI1LTAyLTA0VDE1OjQwOjQzKzAzOjAwIi8+IDwvcmRmOlNlcT4gPC94bXBNTTpIaXN0b3J5PiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8P3hwYWNrZXQgZW5kPSJ3Ij8+/+ICsElDQ19QUk9GSUxFAAEBAAACoGxjbXMEQAAAbW50clJHQiBYWVogB+kAAgAEAAwAJwAVYWNzcEFQUEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPbWAAEAAAAA0y1sY21zAAAAAAAAAAAAAAAAAAAAAAAAAAAA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'''
        icon_data = base64.b64decode(base64_data)
        img = Image.open(io.BytesIO(icon_data))
        photo = ImageTk.PhotoImage(img)
        root.iconphoto(False, photo)

        #root.iconbitmap("sloth.ico")
    except tk.TclError:
        pass
        print("The icon could not be installed (incorrect format or file)")

    root.mainloop()
