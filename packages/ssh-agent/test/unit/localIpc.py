import os
import pathlib
import platform
import socket
import subprocess
import tempfile
import threading
import unittest


class LocalIpc(unittest.TestCase):
    def test_local_services_and_host_boundaries(self):
        binary = pathlib.Path(__file__).resolve().parents[2] / (
            'arm64.bin' if platform.machine() == 'aarch64' else 'x64.bin'
        )
        with tempfile.TemporaryDirectory(prefix='review-ipc-') as directory:
            root = pathlib.Path(directory)
            job = root / 'job'
            job.mkdir()
            protected = root / 'operator'
            protected.write_text('original')
            host_socket = socket.socket(socket.AF_UNIX)
            host_socket.bind(str(root / 'host.sock'))
            host_socket.listen()
            tcp = socket.socket()
            tcp.bind(('127.0.0.1', 0))
            tcp.listen()
            def serve():
                conn, _ = tcp.accept()
                with conn:
                    conn.sendall(b'host tcp')
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            script = r'''
import os, pathlib, socket, sys, threading
job, host, protected, port = sys.argv[1:]
s = socket.socket(socket.AF_UNIX)
s.bind(job + '/local.sock')
s.listen()
def serve():
    conn, _ = s.accept()
    with conn:
        conn.sendall(b'local ipc')
t = threading.Thread(target=serve)
t.start()
with socket.socket(socket.AF_UNIX) as client:
    client.connect(job + '/local.sock')
    assert client.recv(64) == b'local ipc'
t.join()
s.close()
with socket.create_connection(('127.0.0.1', int(port))) as client:
    assert client.recv(64) == b'host tcp'
try:
    with socket.socket(socket.AF_UNIX) as client:
        client.connect(host)
except PermissionError:
    pass
else:
    raise AssertionError('unrelated host socket allowed')
try:
    pathlib.Path(protected).write_text('damaged')
except OSError:
    pass
else:
    raise AssertionError('operator write allowed')
try:
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(host + '.new')
except OSError:
    pass
else:
    raise AssertionError('host socket bind allowed')
pathlib.Path(job, 'experiment.py').write_text('print(42)')
print('local ipc, tcp, experiments and host protection passed')
'''
            try:
                result = subprocess.run([
                    'bwrap', '--ro-bind', '/', '/', '--bind', str(job), str(job),
                    '--dev', '/dev', '--unshare-user', '--unshare-pid', '--proc', '/proc',
                    '--cap-drop', 'ALL', '--', str(binary), '--allow-local-ipc',
                    '--allow-unix-connect', str(job), '--', 'python3', '-c', script,
                    str(job), str(root / 'host.sock'), str(protected), str(tcp.getsockname()[1])
                ], text=True, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('local ipc, tcp, experiments and host protection passed', result.stdout)
                self.assertEqual(protected.read_text(), 'original')
                self.assertEqual((job / 'experiment.py').read_text(), 'print(42)')
            finally:
                host_socket.close()
                tcp.close()


if __name__ == '__main__':
    unittest.main()
