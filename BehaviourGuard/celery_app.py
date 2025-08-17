from tasks import celery
from app import create_app

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        celery.start()
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved