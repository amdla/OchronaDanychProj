# Library Project

## Description
The Library Project is a simple CRUD web application for managing a collection of books in a library. It allows users to add, update, delete, and view books in the library. The project is built using Python with Django, HTML, and CSS.

## Features
- **Add Books:** Add new books using just their ISBN codes - Google Book's API will do the rest for you!
- **Manage users:** Add new users who can loan your books
- **Manage loans:** Easily manage loan lists 


## Installation

### Prerequisites
- Python 3.x
- pip (Python package installer)

### Steps
1. Clone the repository:
    ```sh
    git clone https://github.com/amdla/twitter_project.git
    ```
2. Navigate to the project directory:
    ```sh
    cd twitter_project
    ```
3. Apply migrations:
    ```sh
    python manage.py makemigrations
    python manage.py migrate
    ```
4. Run the application:
    ```sh
    python manage.py runserver
    ```

## Usage
Access the application by opening `http://127.0.0.1:8000` in your web browser. Use the navigation bar to manage different tables and use the search bar to find specific records.

## License
This project is licensed under the MIT License.

## Contact
For any questions or suggestions, please open an issue on GitHub.

## Acknowledgements
- [Django](https://www.djangoproject.com/) - The web framework used.
- [Bootstrap](https://getbootstrap.com/) - Frontend framework for styling.

---
Made with ❤️ by [amdla](https://github.com/amdla).
