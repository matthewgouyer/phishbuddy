# initial setup:

## 1. Clone the repo.

## 2. Create a virtual environment in the root of the project.

### In PyCharm:

Go to File > Settings > Project: <Project Name> > Python Interpreter.
Add a new interpreter by clicking the gear icon and selecting "Add".
   Click Generate new environment.
   Choose "Virtualenv" and select the base interpreter (Python 3.x).
   Click "OK" to create the virtual environment.

Or 

### In Terminal:

Create a virtual environment in the root of the project.
   python -m venv .venv

Activate the virtual environment.
   On Windows:
      .venv\Scripts\activate
   On macOS/Linux:
      source .venv/bin/activate


Now open a new terminal window and complete the following steps:

## 3. Install the dependencies.
pip install -r requirements.txt

   
## 4. Run the following command to start the server:

uvicorn backend.main:app --reload

fast api docs has backend commands for testing

## 5. Run frontend/app.py to start the frontend server.

Either from the terminal 

python frontend/app.py

or from PyCharm directly.

Then open dev server in a browser of your choosing. Should be @ http://127.0.0.1:5000/


extra note, not sure if necessary:
.env version control note:
make an .env file in the root of the project and add the following variables

# .env

ENV_NAME="Development"

BASE_URL="given uvicorn address"

DB_URL="sqlite:///data/urls.db"
