import { Radio } from 'antd';
import React, { useEffect, useState } from 'react';
import { Route, useHistory, useLocation } from 'react-router-dom';
import intl from 'react-intl-universal';
import { trackPageView } from '@app/utils/stat';

import FileUpload from './FileUpload';
import './index.less';
import TaskList from './TaskList';

const NewImport = () => {
  const history = useHistory();
  const location = useLocation();
  const [tab, setTab] = useState('files');
  useEffect(() => {
    const path = location.pathname;
    setTab(path.includes('files') ? 'files' : 'tasks');
    trackPageView('/import');
  }, []);
  const handleTabChange = e => {
    setTab(e.target.value);
    history.push(`/import/${e.target.value}`);
  };
  return (
    <div className="nebua-import-page center-layout">
      <div className="studio-tab-header">
        <Radio.Group
          className="nebula-tab-group"
          value={tab}
          buttonStyle="solid"
          onChange={handleTabChange}
        >
          <Radio.Button value="files">{intl.get('import.uploadFile')}</Radio.Button>
          <Radio.Button value="tasks">{intl.get('import.importData')}</Radio.Button>
        </Radio.Group>
      </div>
      <div>
        <Route
          path={`/import/files`}
          exact={true}
          component={FileUpload}
        />
        <Route
          path={`/import/tasks`}
          exact={true}
          component={TaskList}
        />
      </div>
    </div>
  );
};

export default NewImport;
