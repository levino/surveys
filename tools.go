package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func toolText(text string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func toolJSON(v any) map[string]any {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolErr("could not encode result: " + err.Error())
	}
	return toolText(string(b))
}

func toolErr(msg string) map[string]any {
	res := toolText(msg)
	res["isError"] = true
	return res
}

func toolDefs() []map[string]any {
	str := map[string]any{"type": "string"}
	return []map[string]any{
		{
			"name":        "list_teams",
			"description": "Liste der GitHub-Teams (Verbände), in denen der angemeldete Nutzer Mitglied ist. owner_team beim Anlegen einer Umfrage muss eines dieser Teams sein.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "create_form",
			"description": "Legt eine neue Umfrage/ein Formular an und gibt die öffentliche, nicht erratbare URL zurück. Die Umfrage gehört dem owner_team; nur Mitglieder dieses Teams können Ergebnisse lesen.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"title", "owner_team", "fields"},
				"properties": map[string]any{
					"title":          str,
					"description":    str,
					"owner_team":     map[string]any{"type": "string", "description": "GitHub-Team-Slug, dem die Umfrage gehört"},
					"expires_at":     map[string]any{"type": "string", "description": "Optionales Ablaufdatum (RFC3339 oder YYYY-MM-DD). Danach keine Einsendungen mehr."},
					"allow_multiple": map[string]any{"type": "boolean", "description": "Mehrfach-Einsendungen pro Person erlauben (Default true)"},
					"fields": map[string]any{
						"type":        "array",
						"description": "Felddefinitionen",
						"items": map[string]any{
							"type":     "object",
							"required": []string{"key", "label", "type"},
							"properties": map[string]any{
								"key":        map[string]any{"type": "string", "description": "Technischer Schlüssel [a-z0-9_]+"},
								"label":      str,
								"type":       map[string]any{"type": "string", "enum": []string{"text", "textarea", "email", "select", "radio", "number", "checkbox"}},
								"required":   map[string]any{"type": "boolean"},
								"help":       str,
								"max_length": map[string]any{"type": "integer"},
								"options":    map[string]any{"type": "array", "items": str, "description": "Für select/radio"},
							},
						},
					},
				},
			},
		},
		{
			"name":        "list_forms",
			"description": "Listet alle Umfragen, die einem Team des Nutzers gehören.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "get_form",
			"description": "Liest eine Umfrage inkl. Felddefinition und Anzahl Einsendungen.",
			"inputSchema": map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": str}},
		},
		{
			"name":        "update_form",
			"description": "Ändert eine Umfrage (Titel, Beschreibung, Status active/disabled, Ablaufdatum, Felder).",
			"inputSchema": map[string]any{
				"type": "object", "required": []string{"id"},
				"properties": map[string]any{
					"id": str, "title": str, "description": str,
					"status":     map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
					"expires_at": map[string]any{"type": "string", "description": "RFC3339/YYYY-MM-DD, oder \"\" zum Entfernen"},
					"fields":     map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
				},
			},
		},
		{
			"name":        "disable_form",
			"description": "Deaktiviert eine Umfrage (nimmt keine Einsendungen mehr an).",
			"inputSchema": map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": str}},
		},
		{
			"name":        "delete_form",
			"description": "Löscht eine Umfrage samt aller Einsendungen. Unwiderruflich.",
			"inputSchema": map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": str}},
		},
		{
			"name":        "list_submissions",
			"description": "Liest die Einsendungen einer Umfrage (JSON). Optional since (RFC3339/ms), limit, offset.",
			"inputSchema": map[string]any{
				"type": "object", "required": []string{"form_id"},
				"properties": map[string]any{
					"form_id": str,
					"since":   map[string]any{"type": "string", "description": "Nur Einsendungen nach diesem Zeitpunkt (RFC3339 oder Unix-ms)"},
					"limit":   map[string]any{"type": "integer"},
					"offset":  map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "export_submissions",
			"description": "Exportiert alle Einsendungen einer Umfrage als CSV (Default) oder JSON.",
			"inputSchema": map[string]any{
				"type": "object", "required": []string{"form_id"},
				"properties": map[string]any{
					"form_id": str,
					"format":  map[string]any{"type": "string", "enum": []string{"csv", "json"}},
				},
			},
		},
		{
			"name":        "delete_submission",
			"description": "Löscht eine einzelne Einsendung.",
			"inputSchema": map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": str}},
		},
	}
}

func (a *App) dispatchTool(name string, args json.RawMessage, ctx *AuthContext) map[string]any {
	res, err := a.callTool(name, args, ctx)
	if err != nil {
		return toolErr(err.Error())
	}
	return res
}

func (a *App) callTool(name string, args json.RawMessage, ctx *AuthContext) (map[string]any, error) {
	switch name {
	case "list_teams":
		return toolJSON(map[string]any{"teams": ctx.Teams}), nil

	case "create_form":
		var in struct {
			Title         string     `json:"title"`
			Description   string     `json:"description"`
			OwnerTeam     string     `json:"owner_team"`
			ExpiresAt     string     `json:"expires_at"`
			AllowMultiple *bool      `json:"allow_multiple"`
			Fields        []FieldDef `json:"fields"`
		}
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, err
		}
		if !ctx.isMember(in.OwnerTeam) {
			return toolErr(fmt.Sprintf("Du bist kein Mitglied des Teams %q. Deine Teams: %s", in.OwnerTeam, strings.Join(ctx.teamSlugs(), ", "))), nil
		}
		expires, err := parseExpiry(in.ExpiresAt)
		if err != nil {
			return nil, err
		}
		allowMultiple := true
		if in.AllowMultiple != nil {
			allowMultiple = *in.AllowMultiple
		}
		form, err := a.createForm(createFormInput{
			Title: in.Title, Description: in.Description, Fields: in.Fields,
			OwnerTeam: in.OwnerTeam, ExpiresAt: expires, AllowMultiple: allowMultiple,
		}, ctx.User.GitHubID)
		if err != nil {
			return nil, err
		}
		return toolJSON(map[string]any{
			"id": form.ID, "slug": form.Slug, "url": form.publicURL(a.cfg.BaseURL),
			"owner_team": form.OwnerTeam, "status": form.Status,
		}), nil

	case "list_forms":
		forms, err := a.listFormsForTeams(ctx.teamSlugs())
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, 0, len(forms))
		for _, f := range forms {
			n, _ := a.countSubmissions(f.ID)
			out = append(out, map[string]any{
				"id": f.ID, "title": f.Title, "slug": f.Slug, "url": f.publicURL(a.cfg.BaseURL),
				"owner_team": f.OwnerTeam, "status": f.Status, "submissions": n,
				"expires_at": isoOrEmpty(f.ExpiresAt), "created_at": isoMs(f.CreatedAt),
			})
		}
		return toolJSON(map[string]any{"forms": out}), nil

	case "get_form":
		form, err := a.requireForm(args, ctx)
		if err != nil {
			return a.formAccessErr(err)
		}
		n, _ := a.countSubmissions(form.ID)
		return toolJSON(map[string]any{
			"id": form.ID, "title": form.Title, "description": form.Description, "slug": form.Slug,
			"url": form.publicURL(a.cfg.BaseURL), "owner_team": form.OwnerTeam, "status": form.Status,
			"allow_multiple": form.AllowMultiple, "expires_at": isoOrEmpty(form.ExpiresAt),
			"fields": form.Fields, "submissions": n, "created_at": isoMs(form.CreatedAt),
		}), nil

	case "update_form":
		form, err := a.requireForm(args, ctx)
		if err != nil {
			return a.formAccessErr(err)
		}
		var in struct {
			Title       *string     `json:"title"`
			Description *string     `json:"description"`
			Status      *string     `json:"status"`
			ExpiresAt   *string     `json:"expires_at"`
			Fields      *[]FieldDef `json:"fields"`
		}
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, err
		}
		patch := formPatch{Title: in.Title, Description: in.Description, Status: in.Status, Fields: in.Fields}
		if in.ExpiresAt != nil {
			ms, err := parseExpiry(*in.ExpiresAt)
			if err != nil {
				return nil, err
			}
			patch.ExpiresAt = &ms
		}
		updated, err := a.updateForm(form.ID, patch)
		if err != nil {
			return nil, err
		}
		return toolJSON(map[string]any{"id": updated.ID, "status": updated.Status, "title": updated.Title, "expires_at": isoOrEmpty(updated.ExpiresAt)}), nil

	case "disable_form":
		form, err := a.requireForm(args, ctx)
		if err != nil {
			return a.formAccessErr(err)
		}
		disabled := "disabled"
		if _, err := a.updateForm(form.ID, formPatch{Status: &disabled}); err != nil {
			return nil, err
		}
		return toolText("Umfrage " + form.ID + " deaktiviert."), nil

	case "delete_form":
		form, err := a.requireForm(args, ctx)
		if err != nil {
			return a.formAccessErr(err)
		}
		ok, err := a.deleteForm(form.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return toolErr("Umfrage nicht gefunden"), nil
		}
		return toolText("Umfrage " + form.ID + " gelöscht."), nil

	case "list_submissions":
		var in struct {
			FormID string `json:"form_id"`
			Since  string `json:"since"`
			Limit  int    `json:"limit"`
			Offset int    `json:"offset"`
		}
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, err
		}
		form, err := a.formByIDForUser(in.FormID, ctx)
		if err != nil {
			return a.formAccessErr(err)
		}
		since, err := parseExpiry(in.Since)
		if err != nil {
			return nil, err
		}
		subs, err := a.listSubmissions(form.ID, since, in.Limit, in.Offset)
		if err != nil {
			return nil, err
		}
		return toolJSON(map[string]any{"form_id": form.ID, "count": len(subs), "submissions": submissionsForOutput(subs)}), nil

	case "export_submissions":
		var in struct {
			FormID string `json:"form_id"`
			Format string `json:"format"`
		}
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, err
		}
		form, err := a.formByIDForUser(in.FormID, ctx)
		if err != nil {
			return a.formAccessErr(err)
		}
		subs, err := a.listSubmissions(form.ID, 0, 1000000, 0)
		if err != nil {
			return nil, err
		}
		if in.Format == "json" {
			return toolJSON(submissionsForOutput(subs)), nil
		}
		return toolText(exportCSV(form, subs)), nil

	case "delete_submission":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, err
		}
		formID, err := a.submissionFormID(in.ID)
		if err != nil {
			return nil, err
		}
		if formID == "" {
			return toolErr("Einsendung nicht gefunden"), nil
		}
		if _, err := a.formByIDForUser(formID, ctx); err != nil {
			return a.formAccessErr(err)
		}
		if _, err := a.deleteSubmission(in.ID); err != nil {
			return nil, err
		}
		return toolText("Einsendung " + in.ID + " gelöscht."), nil

	default:
		return toolErr("unbekanntes Tool: " + name), nil
	}
}

var (
	errFormNotFound  = fmt.Errorf("not_found")
	errFormForbidden = fmt.Errorf("forbidden")
)

func (a *App) requireForm(args json.RawMessage, ctx *AuthContext) (*Form, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, err
	}
	return a.formByIDForUser(in.ID, ctx)
}

func (a *App) formByIDForUser(id string, ctx *AuthContext) (*Form, error) {
	form, err := a.getFormByID(id)
	if err != nil {
		return nil, err
	}
	if form == nil {
		return nil, errFormNotFound
	}
	if !ctx.isMember(form.OwnerTeam) {
		return nil, errFormForbidden
	}
	return form, nil
}

func (a *App) formAccessErr(err error) (map[string]any, error) {
	switch err {
	case errFormNotFound:
		return toolErr("Umfrage nicht gefunden"), nil
	case errFormForbidden:
		return toolErr("Kein Zugriff: die Umfrage gehört einem Team, in dem du nicht Mitglied bist."), nil
	default:
		return nil, err
	}
}

func submissionsForOutput(subs []*Submission) []map[string]any {
	out := make([]map[string]any, 0, len(subs))
	for _, s := range subs {
		out = append(out, map[string]any{
			"id": s.ID, "created_at": isoMs(s.CreatedAt), "values": s.Values,
		})
	}
	return out
}

func exportCSV(form *Form, subs []*Submission) string {
	var buf bytes.Buffer
	wr := csv.NewWriter(&buf)
	header := []string{"id", "created_at"}
	for _, f := range form.Fields {
		header = append(header, f.Key)
	}
	_ = wr.Write(header)
	for _, s := range subs {
		row := []string{s.ID, isoMs(s.CreatedAt)}
		for _, f := range form.Fields {
			row = append(row, s.Values[f.Key])
		}
		_ = wr.Write(row)
	}
	wr.Flush()
	return buf.String()
}

func parseExpiry(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UnixMilli(), nil
	}
	var ms int64
	if _, err := fmt.Sscan(s, &ms); err == nil && ms > 0 {
		return ms, nil
	}
	return 0, fmt.Errorf("ungültiges Datum %q (erwartet RFC3339, YYYY-MM-DD oder Unix-ms)", s)
}

func isoMs(ms int64) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func isoOrEmpty(ms int64) string { return isoMs(ms) }

var _ = sort.Strings
