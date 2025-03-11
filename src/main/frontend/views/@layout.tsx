
import { useViewConfig } from '@vaadin/hilla-file-router/runtime.js';
import { effect, Signal, signal } from '@vaadin/hilla-react-signals';
import { ProgressBar } from '@vaadin/react-components';
import { Suspense, useEffect } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router';

const vaadin = window.Vaadin as {
  documentTitleSignal: Signal<string>;
};
vaadin.documentTitleSignal = signal('');
effect(() => {
  document.title = vaadin.documentTitleSignal.value;
});

export default function MainLayout() {
  const currentTitle = useViewConfig()?.title ?? '';
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    vaadin.documentTitleSignal.value = currentTitle;
  });

  return (
    <>
      <div className='flex flex-row gap-m p-m'>
        <h1 className="text-l m-0">{vaadin.documentTitleSignal}</h1>
      </div>

      <Suspense fallback={<ProgressBar indeterminate className="m-0" />}>
        <section className="view">
          <Outlet />
        </section>
      </Suspense>
    </>
  );
}