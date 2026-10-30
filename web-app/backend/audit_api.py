from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from security_runtime import setup, audit
from vault_api import database, session

router = APIRouter(prefix='/api/vault')


@router.get('/audit')
def get_audit(user=Depends(session)):
    with database() as db:
        setup(db)
        rows = db.execute('SELECT event,created_at FROM security_audit WHERE account_id=? AND created_at>=strftime("%s","now")-604800 ORDER BY id DESC LIMIT 200', (user['account_id'],)).fetchall()
    return JSONResponse({'events': [{'event': event, 'created_at': stamp} for event, stamp in rows]}, headers={'Cache-Control': 'no-store'})


@router.delete('/audit')
def delete_history(older_than_days: int = 1, user=Depends(session)):
    if older_than_days not in (0, 1, 3, 7):
        raise HTTPException(400, 'Choose all, 1, 3 or 7 days')
    with database() as db:
        setup(db)
        if older_than_days == 0:
            cursor = db.execute('DELETE FROM security_audit WHERE account_id=?', (user['account_id'],))
        else:
            import time
            cutoff = int(time.time()) - older_than_days * 86400
            cursor = db.execute('DELETE FROM security_audit WHERE account_id=? AND created_at<=?', (user['account_id'], cutoff))
        removed = cursor.rowcount
        audit(db, user['account_id'], 'history.clear')
        db.commit()
    return {'deleted': removed}
