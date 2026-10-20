package workbuddy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type GrowthTask struct {
	Code     string `json:"task_code"`
	Status   string `json:"accept_status"`
	Type     string `json:"task_type"`
	Progress struct {
		Current *int64 `json:"current"`
		Target  *int64 `json:"target"`
	} `json:"progress"`
}

func (a *ControlClient) GrowthTasks(ctx context.Context) ([]GrowthTask, error) {
	result, err := a.Call(ctx, ControlRequest{Operation: ControlGrowthTasks})
	if err != nil {
		return nil, err
	}
	var data struct {
		Tasks *[]GrowthTask `json:"tasks"`
	}
	if err = json.Unmarshal(result.Data, &data); err != nil || data.Tasks == nil {
		return nil, fmt.Errorf("workbuddy: missing growth task list")
	}
	seen := make(map[string]bool)
	for _, task := range *data.Tasks {
		if !taskCodePattern.MatchString(task.Code) || seen[task.Code] {
			return nil, fmt.Errorf("workbuddy: invalid or duplicate growth task")
		}
		seen[task.Code] = true
		switch task.Status {
		case "not_accepted", "accepted", "completed", "claimed":
		default:
			return nil, fmt.Errorf("workbuddy: unknown growth task status")
		}
		if task.Progress.Current != nil && *task.Progress.Current < 0 || task.Progress.Target != nil && *task.Progress.Target < 0 {
			return nil, fmt.Errorf("workbuddy: invalid growth progress")
		}
	}
	return *data.Tasks, nil
}
func (a *ControlClient) AcceptGrowthTasks(ctx context.Context, codes []string) error {
	for len(codes) > 0 {
		size := min(20, len(codes))
		part := codes[:size]
		result, err := a.Call(ctx, ControlRequest{Operation: ControlGrowthAccept, TaskCodes: part})
		if err != nil {
			return err
		}
		var data struct {
			Results []struct {
				Code   string `json:"task_code"`
				Status string `json:"status"`
			} `json:"results"`
		}
		if err = json.Unmarshal(result.Data, &data); err != nil {
			return fmt.Errorf("workbuddy: invalid growth acceptance")
		}
		accepted := make(map[string]bool)
		for _, item := range data.Results {
			if item.Status == "accepted" || item.Status == "already_accepted" {
				accepted[item.Code] = true
			}
		}
		for _, code := range part {
			if !accepted[code] {
				return fmt.Errorf("workbuddy: growth acceptance incomplete")
			}
		}
		codes = codes[size:]
	}
	return nil
}

// ReconcileGrowth accepts eligible tasks and claims only completion observed
// from the vendor. It never fabricates report events or pretends a desktop,
// subscription, donation or other real-world action has taken place.
func (a *ControlClient) ReconcileGrowth(ctx context.Context, ledger *JobLedger) (int, error) {
	tasks, err := a.GrowthTasks(ctx)
	if err != nil {
		return 0, err
	}
	var accept []string
	for _, task := range tasks {
		switch task.Code {
		case "wb_wechat_oa_subscribe_task", "Expert_Philanthropy", "RichMeow_Chat", "Library_read", "Buddy_App", "Buddy_App_QQ":
			continue
		}
		if task.Status == "not_accepted" && task.Type != "auto" {
			accept = append(accept, task.Code)
		}
	}
	if len(accept) > 0 {
		if err = a.AcceptGrowthTasks(ctx, accept); err != nil {
			return 0, err
		}
		tasks, err = a.GrowthTasks(ctx)
		if err != nil {
			return 0, err
		}
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	slot := now.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02")
	c, err := a.Load()
	if err != nil {
		return 0, err
	}
	pending := 0
	for _, task := range tasks {
		if task.Status == "claimed" {
			continue
		}
		complete := task.Status == "completed" || (task.Status == "accepted" || task.Type == "auto") && task.Progress.Current != nil && task.Progress.Target != nil && *task.Progress.Target > 0 && *task.Progress.Current >= *task.Progress.Target
		if !complete {
			pending++
			continue
		}
		receipt, _, errClaim := ledger.Run(ctx, c, "growth_claim:"+task.Code, slot, func(ctx context.Context) (JobReceipt, error) {
			result, errCall := a.Call(ctx, ControlRequest{Operation: ControlGrowthClaim, TaskCode: task.Code})
			if errCall != nil {
				return JobReceipt{}, errCall
			}
			return RewardReceipt(result)
		})
		if errClaim != nil {
			return pending, errClaim
		}
		if receipt.Status != "success" {
			pending++
		}
	}
	return pending, nil
}
