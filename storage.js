import { Client } from '@replit/object-storage';

let client;

export function getStorageClient() {
  if (!client) {
    client = new Client();
  }
  return client;
}

export async function uploadFile(key, buffer, contentType) {
  const storage = getStorageClient();
  const result = await storage.uploadFromBytes(key, buffer, {
    contentType,
  });
  if (!result.ok) {
    throw new Error(`Storage upload failed: ${result.error?.message || 'Unknown error'}`);
  }
  return key;
}

export async function uploadFileFromFilename(key, filename, contentType) {
  const storage = getStorageClient();
  const result = await storage.uploadFromFilename(key, filename, {
    contentType,
  });
  if (!result.ok) {
    throw new Error(`Storage upload failed: ${result.error?.message || 'Unknown error'}`);
  }
  return key;
}

export async function downloadFile(key) {
  const storage = getStorageClient();
  const result = await storage.downloadAsBytes(key);
  if (!result.ok) {
    throw new Error(`Storage download failed: ${result.error?.message || 'Unknown error'}`);
  }
  return result.value;
}

export function downloadStream(key) {
  return getStorageClient().downloadAsStream(key);
}

export async function deleteFile(key) {
  const storage = getStorageClient();
  const result = await storage.delete(key);
  if (!result.ok) {
    throw new Error(`Storage delete failed: ${result.error?.message || 'Unknown error'}`);
  }
}

export async function fileExists(key) {
  const storage = getStorageClient();
  const result = await storage.exists(key);
  return result.ok && result.value;
}

export function videoKey(videoId, filename) {
  const ext = filename.split('.').pop();
  return `videos/${videoId}.${ext}`;
}

export function thumbnailKey(videoId) {
  return `thumbnails/${videoId}.jpg`;
}
