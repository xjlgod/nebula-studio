import { Button, Popconfirm, Progress } from 'antd';
import { CheckCircleFilled } from '@ant-design/icons';
import React, { useEffect, useState } from 'react';
import intl from 'react-intl-universal';
import './index.less';
import { ITaskItem, ITaskStatus } from '@app/interfaces/import';
import dayjs from 'dayjs';
import { floor } from 'lodash';
import { getFileSize } from '@app/utils/file';
import Icon from '@app/components/Icon';
interface IProps {
  data: ITaskItem;
  handleStop: (id: number) => void;
  handleDelete: (id: number) => void;
  handleDownload: (id: number) => void;
  onViewLog: (id: number, space: string, taskStatus: ITaskStatus) => void;
}


const COLOR_MAP = {
  'success': {
    from: '#8EDD3F',
    to: '#27AE60',
  },
  'normal': {
    from: '#8EDD3F',
    to: '#27AE60',
  },
  'execption': {
    from: '#EB5757',
    to: '#EB5757',
  },
  'active': {
    from: '#58D7FF',
    to: '#2F80ED',
  },
};
const TaskItem = (props: IProps) => {
  const { 
    data: { 
      space,
      taskID, 
      name, 
      stats: { totalImportedBytes, totalBytes, numFailed, numReadFailed }, 
      taskStatus, 
      taskMessage,
      updatedTime, 
      createdTime 
    }, 
    onViewLog,
    handleDownload,
    handleStop, 
    handleDelete } = props;
  const [status, setStatus] = useState<'success' | 'active' | 'normal' | 'exception' | undefined>(undefined);
  const [extraMsg, setExtraMsg] = useState('');
  const addMsg = () => {
    const info: string[] = [];
    if(numFailed > 0) {
      info.push(intl.get('import.notImported', { total: getFileSize(numFailed) }));
    }
    if(numReadFailed > 0) {
      info.push(intl.get('import.readFailed', { total: getFileSize(numReadFailed) }));
    }
    info.length > 0 && setExtraMsg(info.join(', '));
  };
  useEffect(() => {
    if(taskStatus === ITaskStatus.StatusFinished) {
      setStatus('success');
      addMsg();
    } else if(taskStatus === ITaskStatus.StatusProcessing) {
      setStatus('active');
      addMsg();
    } else {
      setStatus('exception');
      if(taskMessage) {
        setExtraMsg(taskMessage);
      }
    }
  }, [taskStatus]);
  return (
    <div className="task-item">
      <div className="row">
        <span>{intl.get('common.space')}: {space}</span>
        <Button type="link" size="small" onClick={() => handleDownload(taskID)}>
          <Icon type="icon-studio-btn-download" />
          {intl.get('import.downloadConfig')}
        </Button>
      </div>
      <div className="row">
        <div className="progress">
          <div className="progress-info">
            <span className="task-name">
              {name}
              {taskStatus === ITaskStatus.StatusFinished && <span className="complete-info">
                <CheckCircleFilled />
                {intl.get('import.importCompleted')}
                <span className="red">{extraMsg && ` (${extraMsg})`}</span>
              </span>}
              {taskStatus === ITaskStatus.StatusAborted && <span className="error-info">
                {intl.get('import.importFailed')}
                {extraMsg && ` (${extraMsg})`}
              </span>}
              {taskStatus === ITaskStatus.StatusStoped && <span className="error-info">
                {intl.get('import.importStopped')}
              </span>}
            </span>
            <div className="more-info">
              <span>
                {taskStatus !== ITaskStatus.StatusFinished && `${getFileSize(totalImportedBytes)} / `}
                {getFileSize(totalBytes)}{' '}
              </span>
              <span>{dayjs.duration(dayjs.unix(updatedTime).diff(dayjs.unix(createdTime))).format('HH:mm:ss')}</span>
            </div>
          </div>
          <Progress 
            format={percent => `${percent}%`}
            status={status} 
            percent={taskStatus !== ITaskStatus.StatusFinished ? floor(totalImportedBytes / totalBytes * 100, 2) : 100} 
            strokeColor={status && COLOR_MAP[status]} />
        </div>
        <div className="operations">
          {/* <Button className="primary-btn">{intl.get('import.details')}</Button> */}
          <Button className="primary-btn" onClick={() => onViewLog(taskID, space, taskStatus)}>{intl.get('import.viewLogs')}</Button>
          {taskStatus === ITaskStatus.StatusProcessing && 
          <Popconfirm
            placement="left"
            title={intl.get('import.endImport')}
            onConfirm={() => handleStop(taskID)}
            okText={intl.get('common.confirm')}
            cancelText={intl.get('common.cancel')}
          >
            <Button className="cancel-btn">{intl.get('import.endImport')}</Button>
          </Popconfirm>}
          {taskStatus !== ITaskStatus.StatusProcessing && 
          <Popconfirm
            placement="left"
            title={intl.get('common.ask')}
            onConfirm={() => handleDelete(taskID)}
            okText={intl.get('common.confirm')}
            cancelText={intl.get('common.cancel')}
          >
            <Button danger={true}>{intl.get('common.delete')}</Button>
          </Popconfirm>}
        </div>
      </div>
    </div>
  );
};

export default TaskItem;
