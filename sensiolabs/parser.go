package sensiolabs

import (
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	Layout = "Mon, 2 Jan 2006 15:04:05 +0000"
)

type Xml struct {
	XMLName     xml.Name `xml:"rss"`
	LastBuildAt string   `xml:"channel>lastBuildDate"`
	Items       Items    `xml:"channel>item"`
}

type Item struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Link        string `xml:"link"`
	PublishedAt string `xml:"pubDate"`
}
type Items []Item

type Advisory struct {
	Title              string
	Link               string
	CveIdentifier      string
	PublishedAt        time.Time
	PackageName        string
	VulnerableVersions [][]string
}

type Advisories struct {
	Source      string
	LastBuildAt time.Time
	Items       []Advisory
}

func GetAdvisories() (*Advisories, error) {
	var advs Advisories
	rss, err := getXml()
	if err != nil {
		return nil, err
	}

	advs.Source = "Sensiolabs"
	advs.LastBuildAt, _ = time.Parse(Layout, rss.LastBuildAt)

	advs.Items = rss.extractAdvisories()

	return &advs, nil
}

func getXml() (*Xml, error) {
	rss := &Xml{}

	var client http.Client
	resp, err := client.Get("https://security.sensiolabs.org/database.rss")
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	reader := strings.NewReader(string(body))
	decoder := xml.NewDecoder(reader)
	err = decoder.Decode(rss)
	if err != nil {
		return nil, err
	}

	return rss, nil
}

func (rss *Xml) extractAdvisories() []Advisory {
	var advs []Advisory

	for _, item := range rss.Items {
		adv := Advisory{}

		header := strings.Split(item.Title, " - ")
		adv.Title = strings.Join(header[1:], " ")
		adv.Link = item.Link
		adv.PackageName = header[0]
		adv.PublishedAt, _ = time.Parse(Layout, item.PublishedAt)

		desc := strings.Split(item.Description, "\n")
		var versionsRaw []string
		for i, line := range desc {
			line = strings.TrimSpace(line)

			if strings.Contains(line, adv.Title) {
				cve := strings.Replace(line, adv.Title, "", 1)
				if cve != "" {
					adv.CveIdentifier = cve
				} else {
					adv.CveIdentifier = "None"
				}
			}

			if strings.Contains(line, "Affected versions") {
				versionsRaw = desc[i+1:]
			}
		}

		for _, line := range versionsRaw {
			line = strings.TrimSpace(line)
			if line != "" {
				str := strings.Trim(line, "[]")
				version := strings.Split(str, ", ")
				if len(version) == 1 {
					version = append([]string{">=0"}, version...)
				}
				adv.VulnerableVersions = append(adv.VulnerableVersions, version)
			}
		}

		advs = append(advs, adv)
	}

	return advs
}
