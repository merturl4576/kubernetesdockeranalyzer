import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
from analyzer import DockerfileAnalyzer
from models.finding import Finding
from fpdf import FPDF
import csv
import os

# Tema ayarları
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class ModernGUI:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("🔒 Container Hardening Analyzer")
        self.app.geometry("1000x620")
        self.file_paths = []
        self.all_results = []
        self.fixed_outputs = {}

        # Üst panel
        top_frame = ctk.CTkFrame(self.app)
        top_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkButton(top_frame, text="📂 Select Files", command=self.select_files).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="🔍 Analyze", command=self.analyze_files).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="📤 Export Findings", command=self.export_findings).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="🛠 Export Fixed Dockerfile", command=self.export_fixed).pack(side="left", padx=5)

        self.gpt_var = ctk.BooleanVar()
        ctk.CTkCheckBox(top_frame, text="🤖 Use GPT", variable=self.gpt_var).pack(side="left", padx=5)

        # Sonuçlar bölümü
        self.results_frame = ctk.CTkScrollableFrame(self.app, height=420)
        self.results_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Risk skoru etiketi
        self.score_label = ctk.CTkLabel(
            self.app,
            text="Risk Score: 0/10",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.score_label.pack(pady=(0, 5))

        # Footer: lisans + iletişim
        footer = ctk.CTkLabel(
            self.app,
            text="© 2025 Mert Ural – Developed with 💙 | Contact: merturl67@gmail.com",
            text_color="#1E90FF",  # Dodger Blue
            font=ctk.CTkFont(size=12)
        )
        footer.pack(side="bottom", pady=5)

        self.app.mainloop()

    def select_files(self):
        self.file_paths = filedialog.askopenfilenames(
            filetypes=[("Docker/YAML", "*.Dockerfile *.yaml *.yml"), ("All files", "*.*")]
        )

    def analyze_files(self):
        self.all_results.clear()
        self.fixed_outputs.clear()
        score_sum = 0

        for widget in self.results_frame.winfo_children():
            widget.destroy()

        row = 0
        for path in self.file_paths:
            try:
                with open(path, "r") as f:
                    content = f.read()
                analyzer = DockerfileAnalyzer(content, use_gpt=self.gpt_var.get())
                findings = analyzer.analyze()
                score = analyzer.get_score()
                fixed = analyzer.generate_fixed()

                score_sum += score
                self.all_results.extend(findings)
                self.fixed_outputs[path] = fixed

                # Dosya adı
                ctk.CTkLabel(
                    self.results_frame,
                    text=f"📄 {os.path.basename(path)}",
                    font=ctk.CTkFont(weight="bold")
                ).grid(row=row, column=0, columnspan=3, sticky="w", pady=5)
                row += 1

                for f in findings:
                    ctk.CTkLabel(self.results_frame, text=f.level).grid(row=row, column=0, padx=5, pady=2)
                    ctk.CTkLabel(self.results_frame, text=f.message, wraplength=350).grid(row=row, column=1, padx=5, pady=2)
                    ctk.CTkLabel(self.results_frame, text=f.suggestion, wraplength=350).grid(row=row, column=2, padx=5, pady=2)
                    row += 1

            except Exception as e:
                print(f"[ERROR] {path} => {e}")

        avg = score_sum // len(self.file_paths) if self.file_paths else 0
        emoji = "🟢" if avg < 3 else "🟡" if avg <= 6 else "🔴"
        self.score_label.configure(
            text=f"Risk Score: {avg}/10 {emoji}",
            text_color=("green" if avg < 3 else "orange" if avg <= 6 else "red")
        )

    def export_findings(self):
        if not self.all_results:
            messagebox.showerror("No Findings", "No findings to export.")
            return

        fmt = simpledialog.askstring("Export Format", "Enter format (csv, txt, pdf):")
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}")
        if not path:
            return

        try:
            if fmt == "csv":
                with open(path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Level", "Message", "Suggestion"])
                    for finding in self.all_results:
                        writer.writerow([finding.level, finding.message, finding.suggestion])
            elif fmt == "txt":
                with open(path, "w") as f:
                    for finding in self.all_results:
                        f.write(f"{finding.level} | {finding.message} | {finding.suggestion}\n")
            elif fmt == "pdf":
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                pdf.cell(200, 10, txt="Security Findings", ln=True, align="C")
                for finding in self.all_results:
                    pdf.multi_cell(0, 10, f"{finding.level} | {finding.message} | {finding.suggestion}")
                pdf.output(path)
            else:
                messagebox.showerror("Invalid Format", "Please enter a valid format: csv, txt or pdf.")
        except Exception as e:
            print(f"[EXPORT ERROR] {e}")

    def export_fixed(self):
        if not self.fixed_outputs:
            messagebox.showerror("Error", "No fixed output available. Run analysis first.")
            return

        for path, fixed_content in self.fixed_outputs.items():
            save_path = filedialog.asksaveasfilename(
                defaultextension=".Dockerfile",
                filetypes=[("Dockerfile", "*.Dockerfile")],
                initialfile=f"fixed_{os.path.basename(path)}"
            )
            if save_path:
                try:
                    with open(save_path, "w") as f:
                        f.write(fixed_content)
                    messagebox.showinfo("Exported", f"Fixed Dockerfile saved: {save_path}")
                except Exception as e:
                    print(f"[SAVE ERROR] {e}")

if __name__ == "__main__":
    ModernGUI()
