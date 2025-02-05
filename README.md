# Sloth is ollama Report App
This Python script uses tkinter to create a graphical application for generating reports with a local Ollama server. Users input data (name, module, work, qualities), which is sent to the server to generate a review. The app supports settings and dynamic updating of the model list.

This project is a graphical application in Python that uses the `tkinter` library to create reports with the help of a local Ollama server. Users input data such as full name, module, completed work, personal qualities, work qualities, and the start/end of the report. After submitting, the data is sent to the Ollama server to generate a review, which is displayed in the app.

## Features
- Input fields for user data (name, module, work, qualities).
- Dynamic model selection from the Ollama server.
- Settings window to customize server address, prompt template, and quality lists.
- Real-time display of the generated review.

## Installation
1. Install the required libraries:
   ```bash
   pip install requests pillow
   ```
2. Run the application:
   ```bash
   python main.py
   ```

## Usage
1. Enter data in the input fields.
2. Select a model from the dropdown list.
3. Click "Generate Review" to send data to the Ollama server.
4. The server's response will be displayed in the "Review" field.

## Settings
Open the settings window via the "Settings" menu to customize the server address, prompt template, and quality lists.

## License
This project is licensed under the GNU General Public License v3.0 . See the `LICENSE` file for details.

