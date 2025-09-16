# File Uploads

These endpoints handle image uploads.

#### `POST /api/upload/image`

  - **Description:** Uploads an image file. The uploaded image's hash and URL are returned. Requires authentication.
  - **Headers:**
      - `Authorization: Bearer <token>`
      - `Content-Type: multipart/form-data`
  - **Request Body:** A `multipart/form-data` request containing a file field named `file`.
  - **Response Body (Success):**
    ```json
    {
      "message": "Image uploaded successfully",
      "uploader": {
        "studentId": "string",
        "username": "string"
      },
      "imageHash": "string",
      "imageURL": "string"
    }
    ```
