#!/usr/bin/env python3
import os
import sys
import errno
import hashlib
import argparse
from fuse import FUSE, FuseOSError, Operations, fuse_get_context
import logging

# Configure logging to show time, level, and message
logging.basicConfig(
    filename='config_fuse.log',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class Gatekeeper(Operations):
    def __init__(self, target_hash, secret_path):
        self.target_hash = target_hash
        # Extract the base filename (e.g., secrets.yaml) from the full path
        self.secret_name = os.path.basename(secret_path)
        
        # Read the actual file content from the host
        try:
            with open(secret_path, 'rb') as f:
                self.content = f.read()
        except Exception as e:
            logging.info(f"Error reading secret file: {e}")
            sys.exit(1)
            
        self.access_count = 0

    def get_integrity(self, pid):
        """Checks if the process requesting the file matches the allowed hash."""
        try:
            # Note: Accessing /proc/pid/exe may require root or specific capabilities
            with open(f"/proc/{pid}/exe", "rb") as f:
                return hashlib.file_digest(f, "sha256").hexdigest()
        except Exception:
            return False

    def getattr(self, path, fh=None):
        uid, gid, pid = fuse_get_context()
        if path == '/':
            return dict(st_mode=(0o40755), st_nlink=2)
        # Match against the dynamic secret name
        if path == f'/{self.secret_name}':
            return dict(st_mode=(0o100444), st_nlink=1, st_size=len(self.content), st_uid=uid, st_gid=gid)
        raise FuseOSError(errno.ENOENT)

    def readdir(self, path, fh):
        uid, gid, pid = fuse_get_context()
        return ['.', '..', self.secret_name] if path == '/' else []

    def read(self, path, size, offset, fh):
        uid, gid, pid = fuse_get_context()
        if path != f'/{self.secret_name}':
            raise FuseOSError(errno.ENOENT)
        
        _, _, pid = fuse_get_context()

        if (self.access_count > 0):
            logging.info(f"Access Denied: accessed for second time by Process {pid}.")
            raise FuseOSError(errno.EACCES)
               
        # Integrity check: Only the approved binary can see the content
        integrity = self.get_integrity(pid)
        if not integrity or integrity != self.target_hash:
            logging.info(f"Access Denied: Process {pid} hash mismatch [ {integrity} ].")
            raise FuseOSError(errno.EACCES)
        
        self.access_count += 1
        logging.info(f"Access Granted: Process {pid} read the secret file.")
        return self.content[offset:offset + size]

def get_binary_hash(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple FUSE Gatekeeper.")
    parser.add_argument("mountpoint", help="Directory where the secret file will appear")
    parser.add_argument("-f", "--file", required=True, help="Path to the host file to be served as the secret")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--path", help="Path to the allowed binary to derive hash")
    group.add_argument("-s", "--hash", help="Pre-computed SHA256 hash of the allowed binary")
    args = parser.parse_args()

    # Determine target hash
    target_hash = args.hash if args.hash else get_binary_hash(args.path)
    
    mount_dir = os.path.abspath(os.path.expanduser(args.mountpoint))
    if not os.path.exists(mount_dir):
        os.makedirs(mount_dir)

    # Initialize Gatekeeper with the file path
    gatekeeper = Gatekeeper(target_hash, args.file)

    logging.info(f"Gatekeeper active at: {mount_dir}/{gatekeeper.secret_name}")
    logging.info(f"Allowed SHA256: {target_hash}")
    logging.info("Press Ctrl+C to unmount and exit.")

    try:
        FUSE(gatekeeper, mount_dir, foreground=True, nothreads=True, allow_other=True)
    except KeyboardInterrupt:
        logging.info("\nUnmounting...")