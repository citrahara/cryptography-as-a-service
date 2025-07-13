## Instalasi

```bash
pip install Flask cryptography python-dotenv
````

---

## Running

```bash
python app.py
```

File `.env` akan otomatis dibuat saat pertama kali dijalankan

---

## Enkripsi

* **Endpoint:** `/encrypt`
* **Method:** POST
* **URL:** `http://localhost:5000/encrypt`
* **Headers:**

  ```
  Content-Type: application/json
  ```
* **Body:**

  ```json
  {
    "text": "isikan kata/kalimat Anda"
  }
  ```
* **Response:**

  ```json
  {
    "algorithm": "AES",
    "original_text": "text sebelumnya",
    "encrypted_text": "....",
    "iv": "....",
    "tag": "...."
  }
  ```

---

## Dekripsi

* **Endpoint:** `/decrypt`
* **Method:** POST
* **URL:** `http://localhost:5000/decrypt`
* **Headers:**

  ```
  Content-Type: application/json
  ```
* **Body:**

  ```json
  {
    "encrypted_data": "....",
    "key": "...."
  }
  ```
* **Response:**

  ```json
  {
    "decrypted_text": "...."
  }
  ```

```

📌 **Langsung salin**, simpan sebagai `README.md` di root project kamu — beres!
```
