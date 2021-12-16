package oidc

import (
	"context"
	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/pkg/usergroup/model"
	"github.com/goharbor/harbor/src/testing/controller/user"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	retCode := m.Run()
	os.Exit(retCode)
}

func TestAuth_SearchGroup(t *testing.T) {
	a := Auth{}
	res, err := a.SearchGroup(context.TODO(), "grp")
	assert.Nil(t, err)
	assert.Equal(t, model.UserGroup{GroupName: "grp", GroupType: common.OIDCGroupType}, *res)
}

func TestAuth_OnBoardGroup(t *testing.T) {
	a := Auth{}
	g1 := &model.UserGroup{GroupName: "", GroupType: common.OIDCGroupType}
	err1 := a.OnBoardGroup(context.TODO(), g1, "")
	assert.NotNil(t, err1)
	g2 := &model.UserGroup{GroupName: "group", GroupType: common.LDAPGroupType}
	err2 := a.OnBoardGroup(context.TODO(), g2, "")
	assert.NotNil(t, err2)
}

func TestAuth_OnBoardUser(t *testing.T) {
	ctl := user.Controller{}
	ctx := context.TODO()
	a := Auth{userCtl: &ctl}
	user := &models.User{UserID: 1}
	ctl.Mock.On("OnboardOIDCUser", ctx, user).Return(nil)
	err := a.OnBoardUser(ctx, user)
	assert.Nil(t, err)
}
