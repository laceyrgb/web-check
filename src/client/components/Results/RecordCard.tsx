import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

interface Item {
  label?: string;
  value?: string | number;
  href?: string;
}

const RecordCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const summary: string[] = Array.isArray(props.data?.summary) ? props.data.summary : [];
  const items: Item[] = Array.isArray(props.data?.items) ? props.data.items : [];
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      {summary.map((line, index) => (
        <Row key={`summary-${index}`} lbl="Summary" val={line} />
      ))}
      {items.map((item, index) => (
        <Row
          key={`item-${index}`}
          lbl={item.label || 'Item'}
          val={item.value ?? ''}
          link={item.href}
        />
      ))}
      {props.data?.note && <Note>{props.data.note}</Note>}
    </Card>
  );
};

export default RecordCard;
