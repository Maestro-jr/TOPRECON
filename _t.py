import sys, asyncio
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
import qasync
from config.settings import Settings
from transforms import build_registry
from gui import theme
from gui.authorization_gate import GateResult
from gui.main_window import MainWindow
app=QApplication(sys.argv); app.setStyleSheet(theme.stylesheet())
s=Settings(); s.max_depth=2; s.workers=10
w=MainWindow(s, build_registry(), GateResult('example.com','example.com','t',True))
w.resize(1600,940); w.show()
loop=qasync.QEventLoop(app); asyncio.set_event_loop(loop)
def act():
    v=w._graph_view
    subs=[k for k in v._nodes if k.startswith('subdomain:') ]
    ip=[k for k in v._nodes if k.startswith('ip:')]
    target = subs[0] if subs else (ip[0] if ip else None)
    total=len(v._nodes)
    print('nodes total=', total, 'target=', target, flush=True)
    if target:
        w._on_node_clicked(target)
        print('focus bar visible:', w._focus_bar.isVisible(), 'chip=', w._focus_chip.text(), flush=True)
        w._btn_isolate.setChecked(True)  # fires _on_isolate
        vis=sum(1 for it in v._nodes.values() if it.isVisible())
        print('after ISOLATE visible=', vis, 'of', total, '(subtree only)', flush=True)
        w._btn_centralize.setChecked(True)
        print('after CENTRALISE center_key=', (v._center_key or '').split(':')[0], flush=True)
        w._reset_focus()
        vis2=sum(1 for it in v._nodes.values() if it.isVisible())
        print('after EXIT focus visible=', vis2, 'of', total, 'bar_hidden=', not w._focus_bar.isVisible(), flush=True)
    p=w.grab(); p.save('_ui_shot.png')
    print('screenshot saved', p.width(),'x',p.height(), flush=True)
    loop.stop()
with loop:
    loop.call_soon(w.start_scan); QTimer.singleShot(13000, act); loop.run_forever()
print('CLEAN', flush=True)
