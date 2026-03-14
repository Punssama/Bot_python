from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/webhook")
async def handle_webhook(request: Request):
    # Nhận dữ liệu từ GitHub gửi sang
    payload = await request.json()
    
    # In ra màn hình để mình xem "mặt mũi" gói tin
    print("--- CÓ TÍN HIỆU WEBHOOK MỚI! ---")
    
    # Kiểm tra xem ai vừa push code
    if "repository" in payload:
        repo_name = payload["repository"]["full_name"]
        pusher = payload["pusher"]["name"]
        print(f"Bác {pusher} vừa mới push code vào repo: {repo_name}")
        
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    # Chạy ở cổng 5000 (đúng cổng bạn mở Ngrok)
    uvicorn.run(app, host="0.0.0.0", port=5000)