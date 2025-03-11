
import { ViewConfig } from '@vaadin/hilla-file-router/types.js';
import { Button, Card, Notification, Upload, UploadElement } from '@vaadin/react-components';
import { useEffect, useRef } from 'react';

export const config: ViewConfig = {
  title: "Sign Key",
  loginRequired: true
};

const getMyCsrfHeaders: () => Record<string, string> = () => {
  const token = document.querySelector('meta[name="_csrf"]')?.getAttribute('content') || '';
  return { 'X-CSRF-Token': token };
}

const maxFileSizeInMB = 10;
const maxFileSizeInBytes = maxFileSizeInMB * 1024 * 1024;

export default function MainView() {
  const csrfHeaders = getMyCsrfHeaders();
  const uploadRef = useRef<UploadElement>(null);

  useEffect(() => {
    if (!uploadRef.current) {
      return;
    }
    uploadRef.current.i18n.addFiles.many = 'Select Files...';
    uploadRef.current.i18n = { ...uploadRef.current.i18n };
  }, [uploadRef.current]);


  return (
    <>

      <Card theme="elevated">
        <div slot="title">Lapland</div>
        <div slot="subtitle">The Exotic North</div>
        <div>Lapland is the northern-most region of Finland and an active outdoor destination.</div>
      </Card>
      
      <Upload
        target="/rest/key/sign"
        accept=".pub"
        maxFiles={1}
        maxFileSize={maxFileSizeInBytes}
        onFileReject={(event) => {
          Notification.show(event.detail.error);
        }}
        headers={csrfHeaders}
      />
      <Button theme="primary">Submit</Button>
    </>
  );
}