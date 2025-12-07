# JWT & RBAC Demo API

## Опис
Базовий REST API з автентифікацією через JWT, авторизацією за ролями та демонстрацією OAuth2.  
Маршрути:  
- `POST /login` — повертає токен JWT.  
- `GET /profile` — захищений маршрут, повертає `{ sub, role }`.  
- `GET /admin` — доступний тільки для ролі `admin`.  
- `DELETE /users/:id` — доступний тільки для адміна.

---

## Запуск локально

1. Клонувати репозиторій:
git clone https://github.com/yourname/jwt-rbac-demo.git
cd jwt-rbac-demo

Встановити змінну середовища:
$env:JWT_SECRET="ThisIsA32ByteLongSecretForDev1234"

Запустити сервер:
dotnet run

Сервер стартує на http://localhost:5000.

Приклади запитів
1. /login
User:
$body = @{ email="user@example.com"; password="user123" } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "http://localhost:5000/login" -Method POST -Body $body -ContentType "application/json"
$tokenUser = $response.access_token

Admin:
$body = @{ email="admin@example.com"; password="admin123" } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "http://localhost:5000/login" -Method POST -Body $body -ContentType "application/json"
$tokenAdmin = $response.access_token

2. /profile
Без токена → 401:
Invoke-RestMethod -Uri "http://localhost:5000/profile" -Method GET

З токеном user → 200:
Invoke-RestMethod -Uri "http://localhost:5000/profile" -Method GET -Headers @{ Authorization = "Bearer $tokenUser" }

З токеном admin → 200:
Invoke-RestMethod -Uri "http://localhost:5000/profile" -Method GET -Headers @{ Authorization = "Bearer $tokenAdmin" }

3. /admin
User → 403:
Invoke-RestMethod -Uri "http://localhost:5000/admin" -Method GET -Headers @{ Authorization = "Bearer $tokenUser" }

Admin → 200:
Invoke-RestMethod -Uri "http://localhost:5000/admin" -Method GET -Headers @{ Authorization = "Bearer $tokenAdmin" }

4. DELETE /users/:id
User → 403:
Invoke-RestMethod -Uri "http://localhost:5000/users/5" -Method DELETE -Headers @{ Authorization = "Bearer $tokenUser" }

Admin → 200:
Invoke-RestMethod -Uri "http://localhost:5000/users/5" -Method DELETE -Headers @{ Authorization = "Bearer $tokenAdmin" }

5. OAuth2 Demo
Використовував Google OAuth2 Playground.

Скоупи: userinfo.email, userinfo.profile.

Отримав authorization code - обміняв на access token - виконав запит до профільного API.
