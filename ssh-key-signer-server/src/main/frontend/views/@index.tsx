import { ViewConfig } from '@vaadin/hilla-file-router/types.js';

export const config: ViewConfig = {
  title: "Sign Key",
  loginRequired: true
};

const getMyCsrfHeaders: () => Record<string, string> = () => {
  const token = document.querySelector('meta[name="_csrf"]')?.getAttribute('content') || '';
  return { 'X-CSRF-Token': token };
}

export default function MainView() {
  const csrfHeaders = getMyCsrfHeaders();

  return (
    <>
      <span>Under Construction</span>
    </>
  );
}
