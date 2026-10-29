from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from security_runtime import setup
from vault_api import database, require_pico, session

router = APIRouter(prefix='/api/vault')


@router.get('/audit')
def get_audit(user=Depends(session)):
    require_pico()
    with database() as db:
        setup(db)
        rows = db.execute('SELECT event,created_at FROM security_audit WHERE account_id=? AND created_at>=strftime("%s","now")-604800 ORDER BY id DESC LIMIT 200', (user['account_id'],)).fetchall()
    return JSONResponse({'events': [{'event': event, 'created_at': stamp} for event, stamp in rows]}, headers={'Cache-Control': 'no-store'})
