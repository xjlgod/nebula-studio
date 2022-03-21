package importer

import (
	"fmt"

	"github.com/vesoft-inc/nebula-studio/server/pkg/config"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type TaskDb struct {
	*gorm.DB
}

/*
	`InitDB` initialize local sql by open sql and create task_infos table
*/
func InitDB() {
	dbFilePath := config.Cfg.Web.SqlitedbFilePath
	//os.Remove(dbFilePath)
	db, err := gorm.Open(sqlite.Open(dbFilePath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info)})
	if err != nil {
		zap.L().Fatal(fmt.Sprintf("init db fail: %s", err))
	}
	// TODO: AutoMigrate need to optimize
	err = db.AutoMigrate(&TaskInfo{})
	if err != nil {
		zap.L().Fatal(fmt.Sprintf("init taskInfo table fail: %s", err))
		panic(err)
	}
	GetTaskMgr().db = &TaskDb{
		DB: db,
	}
}

// FindTaskInfoByIdAndAddresssAndUser used to check whether the task belongs to the user
func (t *TaskDb) FindTaskInfoByIdAndAddresssAndUser(id int, nebulaAddress, user string) (*TaskInfo, error) {
	taskInfo := new(TaskInfo)
	if err := t.Model(&TaskInfo{}).Where("id = ? AND nebula_address = ? And user = ?", id, nebulaAddress,
		user).First(&taskInfo).Error; err != nil {
		return nil, err
	}
	return taskInfo, nil
}

func (t *TaskDb) InsertTaskInfo(info *TaskInfo) error {
	return t.Create(info).Error
}

func (t *TaskDb) UpdateTaskInfo(info *TaskInfo) error {
	return t.Model(&TaskInfo{}).Where("id = ?", info.ID).Updates(info).Error
}

func (t *TaskDb) DelTaskInfo(ID int) error {
	return t.Delete(&TaskInfo{}, ID).Error
}

func (t *TaskDb) LastId() (int, error) {
	var id int
	if err := t.Raw("SELECT MAX(id) FROM task_infos").Scan(&id).Error; err != nil {
		if err.Error() == "sql: Scan error on column index 0, name \"MAX(id)\": converting NULL to int is unsupported" {
			return 0, nil
		}
		return 0, err
	}
	return id, nil
}

func (t *TaskDb) SelectAllIds(nebulaAddress, username string) ([]int, error) {
	var taskInfos []TaskInfo
	ids := make([]int, 0)
	if err := t.Select("id").Where("nebula_address = ? And username = ?", nebulaAddress, username).Find(&taskInfos).Error; err != nil {
		return nil, err
	}
	for _, taskInfo := range taskInfos {
		ids = append(ids, taskInfo.ID)
	}
	return ids, nil
}
